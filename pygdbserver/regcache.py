# coding=utf-8
from gdb_enums import RegisterStatus


class Regcache(object):
    def __init__(self, tdesc):
        self.tdesc = tdesc
        self.registers_valid = False
        self.registers_owned = True
        self.registers = ""
        self.register_status = [RegisterStatus.REG_UNAVAILABLE] * tdesc.num_registers()

    def register_data(self, n, fetch):
        reg = self.tdesc.reg_defs[n]
        return self.registers[reg.offset / 8: (reg.offset + reg.size) / 8]

    def regcache_register_status(self, regnum):
        return RegisterStatus[self.register_status[regnum]]

    def collect_register_as_string(self, n):
        return self.register_data(n, True).encode("hex")

    def outreg(self, regno):
        """
        Encode a specific register.
        :param int regno: Register number.
        :return: Register's representation
        :rtype: str
        """
        if regno >> 12 > 0:
            buf = "{:08x}".format(regno)
        elif regno >> 8 > 0:
            buf = "{:06x}".format(regno)
        else:
            buf = "{:04x}".format(regno)
        buf += ":" + self.collect_register_as_string(regno) + ";"
        return buf

    def out_reg_name(self, reg_name):
        """
        Encode a specific register.
        :param str reg_name: Register name.
        :return: Register's representation
        :rtype: str
        """
        return self.outreg(self.tdesc.find_regno(reg_name))
