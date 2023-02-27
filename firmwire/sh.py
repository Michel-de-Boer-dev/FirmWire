from avatar2 import *
from pandare import Panda

import logging as log
import capstone
import os

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

#avatar.log.setLevel(log.DEBUG)

boot_file_path_low  = "./modem_40000000.bin"
boot_file_path_high = "./modem_40010000.bin"


stat_st = os.stat( boot_file_path_high )

# Initial startup, may jump to 40000000 later on
avatar.add_memory_range(
    entry_address,
    size=0x10b50, # size of bootfile is slightly less!
    file=boot_file_path_low,
    name="BOOT_LOW",
    permissions="r-x"
)

stat_st = os.stat( boot_file_path_high )

avatar.add_memory_range(
    0x40000000,
    size=stat_st.st_size,
    file=boot_file_path_high,
    name="BOOT_HIGH",
    permissions="rwx"
)

avatar.add_memory_range(0x94000000, 0x1000, name="rwx_scratch", permissions="rwx")

change_state = b"\x1f\x10\x1c\xd5\xe1\x03\x1f\xaa\x21\x00\x00\x32\x21\x00\x18\x32\x01\x11\x1e\xd5\x41\x03\x80\xd2\x21\x40\x1e\xd5\x41\x03\x80\xd2\x01\x40\x1e\xd5\xdf\x3f\x03\xd5\xe0\x03\x9f\xd6"



avatar.init_targets()
qemu.write_register("pc", 0x94000000)
qemu.write_memory(qemu.read_register("pc"), len(change_state), change_state, raw=True )

register_dump(qemu);
qemu.step()# 4
qemu.step()# 8
qemu.step()# c
qemu.step()# 10
qemu.step()# 14
qemu.step()# 18
qemu.step()# 1c
qemu.step()# 20
qemu.step()# 24
qemu.step() # ISB
qemu.step()# ERET

register_dump(qemu);
qemu.write_register("pc", 0)

qemu.step()
exit()


for _ in range(100):
    qemu.step()
    register_dump(qemu)
