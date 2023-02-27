from avatar2 import *
from pandare import Panda

import logging as log
import capstone
import os

class ARM_CORTEX_A15(ARM):
    cpu_model = "cortex-a15"
    qemu_name = "arm"
    gdb_name = "arm"
    angr_name = "arm"
    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_ARM
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_LITTLE_ENDIAN | KS_MODE_ARM
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_LITTLE_ENDIAN | UC_MODE_THUMB

    @staticmethod
    def init(avatar):
        pass

def register_dump(qemu):
        R = qemu.regs
        dump = """\npc:  %08x      lr:  %08x      sp:  %08x
r0:  %08x      r1:  %08x      r2:  %08x
r3:  %08x      r4:  %08x      r5:  %08x
r6:  %08x      r7:  %08x      r8:  %08x
r9:  %08x      r10: %08x      r11: %08x
r12: %08x     cpsr: %08x""" % (
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
            insns=10,
            mode=capstone.CS_MODE_ARM
        ).strip())



avatar = Avatar(
        arch=ARM_CORTEX_A15,
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


avatar.init_targets()
register_dump(qemu);
qemu.step()# branch to boot
qemu.step()# some mcr
# skip the RAS setup.
qemu.write_register("pc", 0xcc)
register_dump(qemu);
for _ in range(100):
    qemu.step()
    register_dump(qemu)
