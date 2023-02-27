from avatar2 import *
from pandare import Panda

import logging as log
import capstone

class ARM_CORTEX_A55(ARM):
    cpu_model = "cortex-a53"
    qemu_name = "aarch64"
    gdb_name = "aarch64"
    angr_name = "aarch64"
    capstone_arch = CS_ARCH_ARM64
    capstone_mode = CS_MODE_LITTLE_ENDIAN
    keystone_arch = KS_ARCH_ARM64
    keystone_mode = KS_MODE_LITTLE_ENDIAN | KS_MODE_ARM
    unicorn_arch = UC_ARCH_ARM64
    unicorn_mode = UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM

    @staticmethod
    def init(avatar):
        pass


avatar = Avatar(
        arch=ARM_CORTEX_A55,
)
avatar.load_plugin("disassembler")
avatar.load_plugin("assembler")

entry_address = 0


assembly_code = b"\x1f\x10\x1c\xd5\x1f\x11\x1c\xd5\x20\x01\x00\x10\x20\x40\x1e\xd5\x00\x01\x80\xd2\x00\x40\x1e\xd5\x04\x11\x3e\xd5\xe0\x03\x9f\xd6\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x42\x42\x38\xd5\x00\x11\x3c\xd5\x00\x00\x61\xb2\x00\x11\x1c\xd5\x80\x00\x80\xd2\x00\x40\x1c\xd5\xc0\x00\x00\x10\x20\x40\x1c\xd5\xe0\x03\x9f\xd6\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x23\xa7\x80\xd2\x43\x42\x38\xd5"


qemu = avatar.add_target(
            PyPandaTarget,
            name="Custom_emulator",
            #gdb_executable="gdb-multiarch",
            #gdb_port=3333,
            #qmp_port=3334,
            entry_address=entry_address,
            log_file="/dev/stdout",

        )
def fake_signal_handler(*args, **kwargs):
    pass
Panda.setup_internal_signal_handler = fake_signal_handler
Panda._setup_internal_signal_handler = fake_signal_handler


avatar.log.setLevel(log.INFO)

avatar.add_memory_range(
    0,
    size=0x10000,
    name="EXAMPLE_MEMORY",
    permissions="rwx"
)
avatar.init_targets()
qemu.write_memory(qemu.read_register("pc"), len(assembly_code), assembly_code, raw=True )

for i in range( 10 ):
    print(f"ins {i+1}")
    qemu.step()
    x0 = hex(qemu.read_register("x0"))[2:]
    x2 = hex(qemu.read_register("x2"))[2:]
    x3 = hex(qemu.read_register("x3"))[2:]
    x4 = hex(qemu.read_register("x4"))[2:]
    pc = hex(qemu.read_register("pc"))[2:]
    print(f"{pc=} {x0=} {x2=} {x3=} {x4=}")

qemu.shutdown()
avatar.shutdown()

