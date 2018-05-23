# coding=utf-8
class Reg(object):
    """ Represents a register. """
    def __init__(self, name, offset, size):
        self.name = name
        self.offset = offset
        self.size = size
