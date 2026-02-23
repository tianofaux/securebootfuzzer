import argparse

parser = argparse.ArgumentParser(
	description="A SecureBoot fuzzer using QEMU via QMP"
)

parser.add_argument(
	"--logs-path",
	help="Logs location",
    default="./securebootfuzzer.log"
)

parser.add_argument(
	"--storage-path",
	help="Storage location for image generation",
    default="./securebootfuzzer_storage/"
)

parser.add_argument(
    "--firmware-variables-path",
    dest="fw_vars_path",
	help="Firmware variables file location, required in split OVMF firmwares",
)

parser.add_argument(
	"-b",
    "--firmware-binary-path",
    dest="fw_binary_path",
	help="Firmware binary file location",
    required=True
)

parser.add_argument(
	"-d",
    "--firmware-symbols-path",
    dest="fw_symbols_path",
	help="Firmware symbols file location"
)

parser.add_argument(
	"-s",
    "--firmware-source-tree",
    dest="fw_source_path",
	help="Firmware source tree location"
)

# hah, BDS reference, get it? because "b", "d", and "s" are in order!
# feel free to make a PR removing the unfunny comment above

parser.add_argument(
    "-a",
	"--architecture",
    dest="vm_cpu_architecture",
	help="The guest VMs' architecture",
    choices=["i386", "x86_64", "aarch64", "riscv32", "riscv64", "ppc", "ppc64"],
    default="x86_64"
)

parser.add_argument(
    "-l",
	"--debug-level",
	help="Minimum log level that will get outputted",
    choices=["trace", "debug", "info", "warning", "error", "critical"],
    default="info"
)

parser.add_argument(
	"--disable-kvm",
    dest="kvm_enabled",
    action="store_false",
	help="Disables KVM acceleration for the guest VMs"
)

parser.add_argument(
	"--enable-vga",
    dest="vga_enabled",
	help="Enables VGA graphics for guest VMs"
)

parser.add_argument(
    "-m",
	"--vm-memory",
	help="The amount of memory in megabytes that each guest VMs will have",
    type=int,
    default=256
)

parser.add_argument(
    "-c",
	"--concurrent-vms",
	help="The amount of concurrently running guest VMs",
    type=int,
    default=1
)
