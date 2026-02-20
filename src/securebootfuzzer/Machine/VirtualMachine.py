from asyncio.subprocess import Process
from asyncio import Task
from typing import Callable, Optional, TYPE_CHECKING
from loguru import logger

import subprocess
import platform
import asyncio

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

        bootdisk_path: str,
        fw_binary_path: str,
        fw_vars_path: Optional[str],
        fw_debug_path: str,
        fw_source_path: str,

        on_anomaly_callback: Callable[[], None],
        on_health_degradation_callback: Callable[[], None],
    ) -> None:
        if kvm_enabled and host_cpu_architecture != vm_cpu_architecture:
            # What did you expect
            raise ValueError(f"KVM cannot be enabled because guest would be {vm_cpu_architecture} while host is {host_cpu_architecture}")

        self.on_anomaly_callback: Callable[[], None] = on_anomaly_callback
        self.on_health_degradation_callback: Callable[[], None] = on_health_degradation_callback

        self._health_monitor: Task | None = None
        self.qemu_process: Process | None = None

        self.cpu_architecture: CpuArchitectureType = vm_cpu_architecture
        self.memory_size_mb: int = memory_size_mb
        self.kvm_enabled: bool = kvm_enabled

        self.bootdisk_path: str = bootdisk_path
        self.fw_binary_path: str = fw_binary_path
        self.fw_vars_path: str | None = fw_vars_path # If split firmware, this is needed
        self.fw_debug_path: str = fw_debug_path
        self.fw_source_path: str = fw_source_path

    async def _health_monitor_proc(self) -> None:
        qemu_process = self.qemu_process
        assert (qemu_process is not None) and (self._health_monitor == asyncio.current_task())

        if TYPE_CHECKING:
            assert qemu_process.stderr # Pyright

        logger.info("Monitoring guest VM health...")
        lines: list[str] = []

        # Evil polling incoming
        while True:
            line = await qemu_process.stderr.readline()
            message = line.decode()

            if (
                "cannot set up" in message.lower()
                or "error" in message.lower()
                or "invalid" in message.lower()
                or (qemu_process.returncode is not None and qemu_process.returncode != 0)
            ):
                logger.error(
                    "QEMU reported an error:\n{}",
                    '\n'.join(lines)
                )

                logger.trace("Calling health callback")
                self.on_health_degradation_callback()

                self.qemu_process = None # Signal death
                break

            lines.append(message)

    async def start(self):
        args = [
            "-net", # Disable networking
            "none",

            "-smp", # UEFI only brings up BSP, so additional cores are useless
            "1",

            "-chardev", # define output
            "stdio,id=char0,signal=off",

            "-serial", # redirect serial logs to output
            "chardev:char0",

            "-m",
            f"{self.memory_size_mb}M",

            "-drive",
            f"if=pflash,format=raw,readonly=on,file={self.fw_binary_path}",
            "-drive",
            f"format=raw,file=fat:rw:{self.bootdisk_path}"
        ]

        if self.kvm_enabled:
            args.append("-enable-kvm")
        else:
            args.append("-accel tcg")

        if self.fw_vars_path:
            args.append(f"-drive if=pflash,format=raw,file={self.fw_vars_path}")


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

    def shutdown(self) -> None:
        assert self.qemu_process is not None

        if TYPE_CHECKING:
            assert self._health_monitor # Pyright

        self.qemu_process.kill()
        self._health_monitor.cancel()
