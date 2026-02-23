from asyncio.subprocess import Process
from asyncio import Task
from typing import Callable, Optional, TYPE_CHECKING
from loguru import logger
from qemu.qmp import QMPClient

import subprocess
import platform
import asyncio
import shutil
import lldb
import os

from securebootfuzzer.Utils import random_str, find_available_port
from securebootfuzzer.Machine.CpuArchitecture import CpuArchitectureType, get_qemu_binary, get_cpu_enum

host_cpu_architecture = get_cpu_enum(platform.machine())

class VirtualMachine:
    """
    QEMU virtual machine abstraction class
    """

    def __init__(
        self,

        vm_cpu_architecture: CpuArchitectureType,
        memory_size_mb: int,
        kvm_enabled: bool,

        vm_root_dir: str,
        fw_binary_path: str,
        fw_vars_path: Optional[str],
        fw_symbols_path: str,
        fw_source_path: str,

        on_anomaly_callback: Callable[[], None],
        on_health_degradation_callback: Callable[[], None],
    ) -> None:
        if kvm_enabled and host_cpu_architecture != vm_cpu_architecture:
            # What did you expect
            raise ValueError(f"KVM cannot be enabled because guest would be {vm_cpu_architecture} while host is {host_cpu_architecture}")

        if not shutil.which(get_qemu_binary(vm_cpu_architecture)):
            logger.critical(
                "`{}` not found in PATH. Required to create qcow2 vmstate sink.",
                get_qemu_binary(vm_cpu_architecture)
            )
            exit(1)

        self.job_counter: int = 0
        self.on_anomaly_callback: Callable[[], None] = on_anomaly_callback
        self.on_health_degradation_callback: Callable[[], None] = on_health_degradation_callback

        self.gdb_port: int = 0
        self.qmp_sock_name: str = f"qmp_{random_str(16)}_fuzz.sock"

        self._health_monitor: Task | None = None
        self.qemu_process: Process | None = None
        self.debugger: lldb.SBDebugger = lldb.SBDebugger.Create()
        self.debugger.SetAsync(True)

        self.qmp_client: QMPClient = QMPClient()
        self.ovmf_process: lldb.SBProcess | None = None

        self.cpu_architecture: CpuArchitectureType = vm_cpu_architecture
        self.memory_size_mb: int = memory_size_mb
        self.kvm_enabled: bool = kvm_enabled

        self.vm_root_dir: str = vm_root_dir
        self.fw_binary_path: str = fw_binary_path
        self.fw_vars_path: str | None = fw_vars_path # If using split firmware, this is needed!
        self.fw_symbols_path: str = fw_symbols_path
        self.fw_source_path: str = fw_source_path

    async def _create_qcow2_vmstate_disk(self) -> None:
        if not shutil.which("qemu-img"):
            logger.critical("`qemu-img` not found in PATH. Required to create qcow2 vmstate sink.")
            exit(1)

        process = await asyncio.create_subprocess_exec(
            "qemu-img",
            "create", "-f", "qcow2", f"{self.vm_root_dir}/vmstate.qcow2", "16M",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        return_code = await process.wait()
        if return_code != 0:
            assert process.stderr
            raise RuntimeError(f"`qemu-img` failed: {await process.stderr.read()}")

    async def _init_debugger(self) -> None:
        target: lldb.SBTarget = self.debugger.CreateTarget(None)
        error = lldb.SBError()
        process: lldb.SBProcess = target.ConnectRemote(
            self.debugger.GetListener(),
            f"connect://localhost:{self.gdb_port}",
            None,
            error
        )

        if not error.Success():
            raise RuntimeError(f"Connection to the GDB remote failed: {error.GetCString()}")

        self.ovmf_process = process

    async def _health_monitor_proc(self) -> None:
        qemu_process = self.qemu_process
        assert qemu_process and (self._health_monitor == asyncio.current_task())

        if TYPE_CHECKING:
            assert qemu_process.stderr # Pyright

        logger.info("Monitoring guest VM health...")
        lines: list[str] = []

        # (not so) evil polling incoming
        while True:
            line = await qemu_process.stderr.readline()
            message = line.decode()
            if message == "": # QEMU was closed
                await self.shutdown()
                break

            lines.append(message)
            if (
                "cannot set up" in message.lower()
                or "error" in message.lower()
                or "invalid" in message.lower()
                or (qemu_process.returncode and qemu_process.returncode != 0)
            ):
                logger.error(
                    "QEMU reported an error. Logs:\n{}",
                    '\n'.join(lines)
                )

                logger.trace("Calling health callback")
                self.on_health_degradation_callback()

                if TYPE_CHECKING:
                    assert self.qemu_process # Pyright

                await self.shutdown()
                break

            logger.trace(message)

    async def _wait_job(self, job_id: str) -> None:
        assert self.qemu_process
        while True:
            jobs: list = await self.qmp_client.execute("query-jobs") # pyright: ignore[reportAssignmentType]

            for job in jobs:
                if job["id"] == job_id:
                    if job["status"] == "concluded":
                        logger.trace("Job '{}': {}", job_id, job)
                        return
                    if job["status"] in ("failed", "aborted", "error"):
                        raise RuntimeError(job)
            #await asyncio.sleep(0.05)

    async def save_snapshot(self, name: str) -> None:
        assert self.qemu_process
        self.job_counter += 1
        job_id = f"sbf-save_snapshot-{self.job_counter}"

        logger.trace(f"Creating snapshot '{name}'")
        logger.trace(await self.qmp_client.execute("snapshot-save", {
            "job-id": job_id,
            "tag": name,
            "vmstate": "vmstate_drive",
            "devices": ["vmstate_drive"]
        }))

        await self._wait_job(job_id)

    async def load_snapshot(self, name: str) -> None:
        assert self.qemu_process
        self.job_counter += 1
        job_id = f"sbf-load_snapshot-{self.job_counter}"

        logger.trace(f"Loading snapshot '{name}'")
        logger.trace(await self.qmp_client.execute("snapshot-load", {
            "job-id": job_id,
            "tag": name,
            "vmstate": "vmstate_drive",
            "devices": ["vmstate_drive"]
        }))

        await self._wait_job(job_id)

    async def resume(self) -> None:
        assert self.qemu_process and self.ovmf_process
        error: lldb.SBError = self.ovmf_process.Continue()

        if not error.Success():
            raise RuntimeError(f"VM resume request failed: {error.GetCString()}")

    async def pause(self) -> None:
        assert self.qemu_process and self.ovmf_process
        error: lldb.SBError = self.ovmf_process.Stop()

        if not error.Success():
            raise RuntimeError(f"VM stop request failed: {error.GetCString()}")

    async def reset(self) -> None:
        assert self.qemu_process
        await self.qmp_client.execute("system_reset")

    async def start(self):
        await self._create_qcow2_vmstate_disk()

        available_gdb_port = find_available_port()
        assert available_gdb_port
        self.gdb_port = available_gdb_port

        args = [
            "-net", # Disable networking
            "none",

            "-smp", # UEFI only brings up BSP (unicore), so additional cores are useless
            "1",

            "-chardev", # define output
            "stdio,id=char0,signal=off",

            "-serial", # redirect serial logs to output
            "chardev:char0",

            "-S", # Halt CPU on reset vector
            "-gdb", # We don't use the -s shorthand, because port would obviously be busy.
            f"tcp::{available_gdb_port}",

            "-qmp",
            f"unix:{self.qmp_sock_name},server=on,wait=on", # Here we instruct QEMU to set up the QMP server at the specified socket

            "-m",
            f"{self.memory_size_mb}M", # self explainatory... isn't it?

            "-drive",
            f"if=pflash,format=raw,readonly=on,file={self.fw_binary_path}", # UEFI code

            # COMMENTED OUT; CF. BELOW.
            #"-drive",
            #f"format=raw,file=fat:ro:{self.vm_root_dir},if=ide,node-name=boot_file", # fuzz target
            # (TODO) MOVE FROM VIRTUAL FAT TO QCOW2: VFAT DOESNT SUPPORT SNAPSHOTS.
            # Therefore, we must figure out a fast alternative to pack EFI files into qcow2 images
            # for blazingly fast fuzzing. This is a hard requirement.

            # (TODO) BREAK AT `EfiBootManagerBoot`, THEN TAKE SNAPSHOT.
            # This will allow us to greatly improve fuzzing throughput instead of resetting the guest,
            # the latter requiring re-entering SEC, PEI, and DXE up to BDS.
            # To accomplish the following, we can monitor the OVMF-generated logs for the BdsDxe.efi binary,
            # as well as the `ImageBase` field in the serial output. We then load the symbols at the delta.
            # This way, we can have source-level debugging.

            # (TODO) SAVE CORE WITH LLDB.
            # This will allow us to search in greater details the source of a crash. Self-explainatory.
            # REF: cf. https://lldb.llvm.org/python_api/lldb.SBProcess.html#lldb.SBProcess.SaveCore

            "-drive",
            f"file={self.vm_root_dir}/vmstate.qcow2,format=qcow2,if=none,node-name=vmstate_drive,cache=none", # for snapshots
            "-device",
            "ide-hd,drive=vmstate_drive,bus=ide.1,unit=0",
        ]

        if self.kvm_enabled:
            args.append("-enable-kvm")
        else:
            args.append("-accel tcg")

        if self.fw_vars_path:
            args.append(f"-drive if=pflash,format=raw,file={self.fw_vars_path}") # UEFI vars (NVRAM)

        binary = get_qemu_binary(self.cpu_architecture)
        logger.trace("Command: {} {}", binary, ' '.join(args))
        self.qemu_process = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        self._health_monitor = asyncio.create_task(self._health_monitor_proc())
        logger.debug("Installed health monitor")

        for i in range(3):
            try:
                await self.qmp_client.connect(self.qmp_sock_name)
                break
            except:
                if i != 4:
                    logger.warning("Couldn't connect to QMP server; waiting for 1 second")
                    await asyncio.sleep(1)
                    continue

                logger.exception("An error occured while connecting to the QMP server")
                if self.qemu_process:
                    await self.shutdown()

                return

        await self._init_debugger()
        logger.debug("Debugger attached to GDB remote")

    async def shutdown(self) -> None:
        assert self.qemu_process

        if TYPE_CHECKING:
            assert self._health_monitor # Pyright

        logger.debug("Disconnecting from GDB remote")
        if self.ovmf_process:
            self.ovmf_process.Clear()
        self.debugger.Clear()

        logger.debug("Uninstalling health monitor")
        self._health_monitor.cancel()
        self._health_monitor = None

        logger.debug("Shutting down guest")
        self.qemu_process.kill()
        self.qemu_process = None

        logger.debug("Disconnecting from QMP server")
        try:
            assert self.qmp_client
            await self.qmp_client.disconnect()
        except:
            logger.exception("Couldn't disconnect from QMP server (this may be expected; check previous logs)")

        if os.path.exists(self.qmp_sock_name):
            os.remove(self.qmp_sock_name)

        logger.debug("Removing vmstate.qcow2 disk")
        if os.path.exists(f"{self.vm_root_dir}/vmstate.qcow2"):
            os.remove(f"{self.vm_root_dir}/vmstate.qcow2")

        self.gdb_port = 0
        logger.info("VM has been shutdown.")
