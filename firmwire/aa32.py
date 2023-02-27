from avatar2 import *
from pandare import Panda

import logging as log
import capstone

class ARM_CORTEX_A55(ARM):
    cpu_model = "cortex-a55"
    qemu_name = "aarch64"
    gdb_name = "aarch64"
    angr_name = "aarch64"
    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_THUMB
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_LITTLE_ENDIAN | KS_MODE_THUMB
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_LITTLE_ENDIAN | UC_MODE_THUMB

    @staticmethod
    def init(avatar):
        pass

def register_dump(qemu):
        R = qemu.regs
        dump = """\npc:  %016x      lr:  %016x      sp:  %016x
r0:  %016x      r1:  %016x      r2:  %016x
r3:  %016x      r4:  %016x      r5:  %016x
r6:  %016x      r7:  %016x      r8:  %016x
r9:  %016x      r10: %016x      r11: %016x
r12: %016x     cpsr: %016x""" % (
            R.pc,
            R.lr,
            R.sp,
            R.r0,
            R.r1,
            R.r2,
            R.r3,
            R.r4,
            R.r5,
            R.r6,
            R.r7,
            R.r8,
            R.r9,
            R.r10,
            R.r11,
            R.r12,
            R.cpsr,
        )

        log.info(dump)

        log.info(
            "lr: "
            + qemu.disassemble_pretty(
                addr=R.lr,
                mode=capstone.CS_MODE_ARM
            ).strip()
        )
        log.info("pc:\n" + qemu.disassemble_pretty(addr=R.pc,
            mode=capstone.CS_MODE_V8,
            insns=10
        ).strip())

avatar = Avatar(
        arch=ARM_CORTEX_A55,
)
avatar.load_plugin("disassembler")
avatar.load_plugin("assembler")

entry_address = 0
assembly_code = b"\x20\x00\x80\xd2\x01\x08\x80\xd2\x40\xc0\x3e\xd5\x41\xc0\x3c\xd5\x42\xc0\x38\xd5"

qemu = avatar.add_target(
            PyPandaTarget,
            name="Custom_emulator",
            gdb_executable="gdb-multiarch",
            gdb_port=3333,
            qmp_port=3334,
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

print("test")
register_dump(qemu)
print("t2")

qemu.step()
register_dump(qemu)

qemu.step()
register_dump(qemu)
qemu.step()
register_dump(qemu)

qemu.shutdown()
avatar.shutdown()
