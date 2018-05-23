from gdb_enums import RegisterStatus

class Regcache(object):
    def __init__(self, tdesc):
        self.tdesc = tdesc
        self.registers_valid = False
        self.registers_owned = True
        self.registers = ""
        self.register_status = [RegisterStatus.REG_UNAVAILABLE] * tdesc.num_registers

    def register_data(self, n, fetch):
        reg = self.tdesc.reg_defs[n]
        return self.registers[reg.offset / 8: (reg.offset + reg.size) / 8]

    def regcache_register_status(self, regnum):
        return RegisterStatus[self.register_status[regnum]]

    def collect_register_as_string(self, n):
        return self.register_data(n, True).encode("hex")

    def outreg(self, regno):
        if regno >> 12 > 0:
            buf = hex(regno)[2:].rjust(8, "0")
        elif regno >> 8 > 0:
            buf = hex(regno)[2:].rjust(6, "0")
        else:
            buf = hex(regno)[2:].rjust(4, "0")
        buf += ":" + self.collect_register_as_string(regno) + ";"
        return buf
