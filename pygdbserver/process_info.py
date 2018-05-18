# coding=utf-8
class ProcessInfo(object):
    """ A class represents a process """

    def __init__(self, ptid):
        """
        c'tor
        :param Ptid ptid: Process ID.
        """
        self.id = ptid
        self.attached = False
        self.gdb_detached = False
        self.symbol_cache = None
        self.breakpoints = []
        self.raw_breakpoints = []
        self.fast_tracepoint_jumps = []
        self.syscalls_to_catch = []
        self.tdesc = None
        self.priv = None

    def gdb_reattached_process(self):
        """ Clear the gdb_detached flag. """
        self.gdb_detached = False
