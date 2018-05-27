# coding=utf-8
from contextlib import contextmanager
from pygdbserver.ptid import Ptid
from pygdbserver.signals import GdbSignal
from pygdbserver.gdb_enums import TargetWaitkind, ResumeKind


class ThreadInfo(object):
    """ Represents a thread. """

    def __init__(self, ptid):
        self.id = ptid
        self.target_data = None
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


class ThreadList(object):
    """ Represents a list of threads, should be created once per server. """

    def __init__(self):
        self.all_threads = []
        self.current_thread = ThreadInfo(Ptid.null_ptid())

    @contextmanager
    def replace_current_thread(self, new_thread):
        """
        Replaces the current thread for this context.
        :param ThreadInfo new_thread: Thread to replace the current with.
        """
        saved_thread = self.current_thread
        self.current_thread = new_thread
        try:
            yield
        finally:
            self.current_thread = saved_thread

    def target_running(self):
        """
        Check if any threads are running.
        :return: If any threads are running.
        :rtype: bool
        """
        return bool(self.all_threads)

    def add_thread(self, thread_id, target_data=""):
        """
        Add new thread to all threads.
        :param Ptid thread_id: Thread's id.
        :param str target_data: Target's data.
        :return: New thread.
        :rtype: ThreadInfo
        """
        new_thread = ThreadInfo(thread_id)
        new_thread.last_resume_kind = ResumeKind.RESUME_CONTINUE
        new_thread.last_status.kind = TargetWaitkind.IGNORE
        self.all_threads.append(new_thread)
        if self.current_thread is None:
            self.current_thread = new_thread
        new_thread.target_data = target_data
        return new_thread

    def find_thread(self, ptid):
        """
        Find a thread by matching `ptid`.
        :param Ptid ptid: Thread's id.
        :return: Existing thread with matching id.
        :rtype: ThreadInfo
        """
        try:
            return filter(lambda thread: thread.id == ptid, self.all_threads)[0]
        except IndexError:
            return None
