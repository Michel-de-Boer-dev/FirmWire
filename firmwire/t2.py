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
# assembly_code = b"\x40\xc0\x3e\xd5\x41\xc0\x3c\xd5\x42\xc0\x38\xd5"
'''
0x0000000000000000:  40 C0 3E D5    mrs x0, rmr_el3
0x0000000000000004:  41 C0 3C D5    mrs x1, rmr_el2
0x0000000000000008:  42 C0 38 D5    mrs x2, rmr_el1
'''

# assembly_code = b"\x00\x11\x3e\xd5" # MRS x0, SCR_EL3
# assembly_code = b"\x40\x42\x38\xd5" # mrs x0, CurrentEL

#mrs x0, SPSR_EL3
# assembly_code = b"\x00\x40\x3e\xd5"


"""
mov x0, 0xff
msr SPSR_EL3, x0
mrs x1, SPSR_EL3
"""
# assembly_code =b"\xe0\x1f\x80\xd2\x00\x40\x1e\xd5\x01\x40\x3e\xd5"
assembly_code = b"\xa0\x00\x00\x10\x20\x40\x1e\xd5\x00\x01\x80\xd2\x00\x40\x1e\xd5\xe0\x03\x9f\xd6\x42\x42\x38\xd5"
"""
0x0000000000000000:  A0 00 00 10    adr  x0, #0x14
0x0000000000000004:  20 40 1E D5    msr  elr_el3, x0
0x0000000000000008:  00 01 80 D2    movz x0, #0x8
0x000000000000000c:  00 40 1E D5    msr  spsr_el3, x0
0x0000000000000010:  E0 03 9F D6    eret 
0x0000000000000014:  42 42 38 D5    mrs  x2, currentel

"""

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


avatar.log.setLevel(log.DEBUG)

avatar.add_memory_range(
    0,
    size=0x10000,
    name="EXAMPLE_MEMORY",
    permissions="rwx"
)
avatar.init_targets()
qemu.write_memory(qemu.read_register("pc"), len(assembly_code), assembly_code, raw=True )

print("First dump:")
register_dump(qemu)
print("First ins: addr x0, in_el2")
qemu.step()
register_dump(qemu)

print("2nd ins: msr ELR_EL3, x0 ")
qemu.step()
register_dump(qemu)

print("3rd ins: mov x0, 8")
qemu.step()
register_dump(qemu)

print("4th ins: msr SPSR_EL3, x0")
qemu.step()
register_dump(qemu)


print("5th ins: eret")
qemu.step()
register_dump(qemu)

print("6th ins: mrs x2, CurrentEL")
qemu.step()
register_dump(qemu)

qemu.shutdown()
avatar.shutdown()

