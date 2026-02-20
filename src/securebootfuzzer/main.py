from loguru import logger

import qemu.qmp
import asyncio
import sys

sys.path.append("/usr/lib/python3.14/site-packages")
import lldb # let's pray that this works in different environments for now!!

from securebootfuzzer.Machine.VirtualMachine import VirtualMachine, CpuArchitectureType, get_cpu_enum
from securebootfuzzer.CliParser import parser

def stub():
    pass

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

    # For now I just want to see if bringing up vms work
    guest = VirtualMachine(
        vm_cpu_architecture,
        args.vm_memory,
        True,
        args.storage_path,
        args.fw_binary_path,
        None,
        "",
        "",

        on_anomaly_callback = stub,
        on_health_degradation_callback= stub,
    )

    await guest.start()
    logger.info("Started guest!")

    await asyncio.sleep(5)

    if guest.qemu_process:
        guest.shutdown()

def sync_main() -> None:
    asyncio.run(main())
