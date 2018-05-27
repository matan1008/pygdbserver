# coding=utf-8
from pygdbserver.signals import GdbSignal
from pygdbserver.gdb_enums import TargetWaitkind, ResumeKind


class ThreadInfo(object):
    def __init__(self, ptid):
        self.id = ptid
        self.thread_data = None
        self.regcache_data = None
        self.last_resume_kind = None
        self.last_status = None
        self.status_pending_p = True
        self.while_stepping = []
        self.btrace = None

    def gdb_wants_thread_stopped(self):
        """
        Set this inferior threads's state as "want-stopped". We won't
        resume this thread until the client gives us another action for
        it.
        """
        self.last_resume_kind = ResumeKind.RESUME_STOP
        if self.last_status.kind == TargetWaitkind.IGNORE:
            # Most threads are stopped implicitly (all-stop); tag that with signal 0.
            self.last_status.kind = TargetWaitkind.STOPPED
            self.last_status.sig = GdbSignal.GDB_SIGNAL_0

    def set_pending_status(self):
        """
        If the thread is stopped with an interesting event, mark it as having a pending event.
        """
        if self.last_status.kind != TargetWaitkind.STOPPED or (
                    self.last_status.sig not in (GdbSignal.GDB_SIGNAL_0, GdbSignal.GDB_SIGNAL_TRAP)):
            self.status_pending_p = True

    def is_status_pending(self):
        """ If the thread might have an event to report. """
        return self.status_pending_p
