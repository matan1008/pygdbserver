from pygdbserver.gdb_enums import TargetWaitkind
from pygdbserver.signals import gdb_signal_to_symbol_string, GdbSignal


class TargetWaitStatus(object):
    def __init__(self, related_pid=None):
        self.kind = TargetWaitkind.TARGET_WAITKIND_EXITED
        self.integer = 0  # exit status
        self.sig = GdbSignal.GDB_SIGNAL_0
        self.related_pid = related_pid
        self.execd_pathname = ""
        self.syscall_number = 0

    def target_waitstatus_to_string(self):
        """ Return a pretty printed form of target_waitstatus. """
        kind_str = "status.kind = "
        if self.kind is TargetWaitkind.TARGET_WAITKIND_EXITED:
            return "{}exited, status = {}".format(kind_str, self.integer)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_STOPPED:
            return "{}stopped, signal = {}".format(kind_str, gdb_signal_to_symbol_string(self.sig))
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_SIGNALLED:
            return "{}signalled, signal = {}".format(kind_str, gdb_signal_to_symbol_string(self.sig))
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_LOADED:
            return "{}loaded".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_FORKED:
            return "{}forked".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_VFORKED:
            return "{}vforked".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_EXECD:
            return "{}execd".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_VFORK_DONE:
            return "{}vfork-done".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_SYSCALL_ENTRY:
            return "{}entered syscall".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_SYSCALL_RETURN:
            return "{}exited syscall".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_SPURIOUS:
            return "{}spurious".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_IGNORE:
            return "{}ignore".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_NO_HISTORY:
            return "{}no-history".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_NO_RESUMED:
            return "{}no-resumed".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_THREAD_CREATED:
            return "{}thread created".format(kind_str)
        elif self.kind is TargetWaitkind.TARGET_WAITKIND_THREAD_EXITED:
            return "{}thread exited, status = {}".format(kind_str, self.integer)
        else:
            return "{}unknown???".format(kind_str)
