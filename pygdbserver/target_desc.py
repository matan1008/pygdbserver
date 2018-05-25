from reg import Reg

class TargetDesc(object):
    def __init__(self, reg_defs, registers_size, expedite_regs, xmltarget):
        self.reg_defs = reg_defs
        self.registers_size = registers_size
        self.expedite_regs = expedite_regs
        self.xmltarget = xmltarget

    def num_registers(self):
        """
        Return number of registers.
        :return: Number of registers.
        :rtype: int
        """
        return len(self.reg_defs)

    @staticmethod
    def copy_target_description(src):
        return TargetDesc(
            src.reg_defs,
            src.registers_size,
            src.expedite_regs,
            src.xmltarget
        )

    def init_target_desc(self):
        offset = 0
        for reg_def in self.reg_defs:
            reg_def.offset = offset
            offset += reg_def.size
        self.registers_size = offset / 8

    def find_regno(self, name):
        for index, reg_def in enumerate(self.reg_defs):
            if reg_def.name == name:
                return index
