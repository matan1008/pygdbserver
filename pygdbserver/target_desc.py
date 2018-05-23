from reg import Reg

class TargetDesc(object):
    def __init__(self, reg_defs, num_registers, registers_size, expedite_regs, xmltarget):
        self.reg_defs = reg_defs
        self.num_registers = num_registers
        self.registers_size = registers_size
        self.expedite_regs = expedite_regs
        self.xmltarget = xmltarget

    @staticmethod
    def copy_target_description(src):
        return TargetDesc(
            src.reg_defs,
            src.num_registers,
            src.registers_size,
            src.expedite_regs,
            src.xmltarget
        )

    def init_target_desc(self):
        offset = 0
        for i in range(self.num_registers):
            self.reg_defs[i].offset = offset
            offset += self.reg_defs[i].size
        self.registers_size = offset / 8

    def find_regno(self, name):
        for i in range(self.num_registers):
            if self.reg_defs[i].name == name:
                return i
