from enum import Enum

from enum import Enum

class CpuArchitectureType(Enum):
    # Please add more if there's any that's missing (that is supported by EDK-II that is!)
    X86_32 = 1 # For i386/i686
    X86_64 = 2 # For x86_64/amd64
    AARCH64 = 3
    RISC_V_32 = 4
    RISC_V_64 = 5
    POWERPC_32 = 6
    POWERPC_64 = 7

machine_mapping = {
    'i386': CpuArchitectureType.X86_32,
    'i686': CpuArchitectureType.X86_32,
    'x86_64': CpuArchitectureType.X86_64,
    'amd64': CpuArchitectureType.X86_64,
    'aarch64': CpuArchitectureType.AARCH64,
    'riscv32': CpuArchitectureType.RISC_V_32,
    'riscv64': CpuArchitectureType.RISC_V_64,
    'ppc': CpuArchitectureType.POWERPC_32,
    'ppc64': CpuArchitectureType.POWERPC_64,
}

qemu_command_mapping = {
    CpuArchitectureType.X86_32: "qemu-system-i386",
    CpuArchitectureType.X86_64: "qemu-system-x86_64",
    CpuArchitectureType.AARCH64: "qemu-system-aarch64",
    CpuArchitectureType.RISC_V_32: "qemu-system-riscv32",
    CpuArchitectureType.RISC_V_64: "qemu-system-riscv64",
    CpuArchitectureType.POWERPC_32: "qemu-system-ppc",
    CpuArchitectureType.POWERPC_64: "qemu-system-ppc64",
}

def get_cpu_enum(cpu_arch: str) -> CpuArchitectureType:
    if not cpu_arch in machine_mapping.keys():
        raise ValueError(f"CPU type '{cpu_arch}' is either invalid or not supported by EDK-II")

    return machine_mapping[cpu_arch]

def get_qemu_binary(cpu_arch: CpuArchitectureType) -> str:
    return qemu_command_mapping[cpu_arch]
