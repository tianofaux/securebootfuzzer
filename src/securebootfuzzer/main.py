from loguru import logger

import asyncio
import shutil
import sys
import os

sys.path.append("/usr/lib/python3.14/site-packages") # enables LLDB import

from securebootfuzzer.Machine.VirtualMachine import VirtualMachine, CpuArchitectureType, get_cpu_enum
from securebootfuzzer.CliParser import parser

def prune_dead_guests(guests: list[VirtualMachine]) -> list[VirtualMachine]:
    guests[:] = [
        guest
        for guest in guests
        if guest.qemu_process is not None
        and guest.qemu_process.returncode is None
    ]

    return guests

def stub():
    return

@logger.catch
async def main() -> None:
    args = parser.parse_args()
    debug_level = args.debug_level.upper()

    logger.remove(0)
    logger.add(sys.stderr, level=debug_level)
    logger.add(
        args.logs_path,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
        level=debug_level
    )

    vm_cpu_architecture = get_cpu_enum(args.vm_cpu_architecture)

    logger.info("Tianofaux says Bonjour!")
    logger.info("Will be fuzzing UEFI firmware '{}' for architecture '{}'", args.fw_binary_path, vm_cpu_architecture)

    # bring up
    guests: list[VirtualMachine] = []
    for i in range(args.concurrent_vms):
        vm_root_dir = f"{args.storage_path}/vm_{i}"
        os.mkdir(vm_root_dir)

        guest = VirtualMachine(
            vm_cpu_architecture,
            args.vm_memory,
            args.kvm_enabled,
            vm_root_dir,
            args.fw_binary_path,
            args.fw_vars_path,
            args.fw_symbols_path,
            args.fw_source_path,
            on_health_degradation_callback=stub,
            on_anomaly_callback=stub
        )

        guests.append(guest)
        await guest.start()
        await guest.save_snapshot("reset_vector") # CPU is disabled at this instant. We are at the reset vector.
        await guest.resume()

    logger.debug("Testing loading reset vector snapshot")

    for i in range(5):
        logger.debug("Testing iter {}", i)
        for guest in prune_dead_guests(guests):
            await guest.load_snapshot("reset_vector")
        await asyncio.sleep(1)

    logger.debug("Shutting down all guests")

    for guest in prune_dead_guests(guests):
        await guest.shutdown()
        shutil.rmtree(guest.vm_root_dir)

def sync_main() -> None:
    asyncio.run(main())
