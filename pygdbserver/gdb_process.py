# coding=utf-8
"""
All code required for managing processes.
"""
from pygdbserver.ptid import Ptid


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


class ProcessList(object):
    """ Represents a list of processes, should be created once per server. """

    def __init__(self):
        self.all_processes = []
        self.current_thread = None

    def __iter__(self):
        return self.all_processes.__iter__()

    def add_process(self, pid, attached):
        """
        Add new process to all processes.
        :param int pid: Process's id.
        :param bool attached: True if if this child process was attached rather than spawned.
        :return: New process.
        :rtype: ProcessInfo
        """
        new_process = ProcessInfo(Ptid.from_pid(pid))
        new_process.attached = attached
        self.all_processes.append(new_process)
        return new_process

    def find_process(self, ptid):
        """
        Find a process by matching `ptid`.
        :param Ptid ptid: Process's id.
        :rtype: ProcessInfo
        """
        try:
            return filter(lambda process: process.id == ptid, self.all_processes)[0]
        except IndexError:
            return None
