# coding=utf-8
""" Module for ThreadResume class. """
from pygdbserver.ptid import Ptid
from pygdbserver.gdb_enums import ResumeKind
from pygdbserver.pygdbserver_exceptions import VcontActionDecodingError
from pygdbserver.signals import GdbSignal, gdb_signal_to_host, gdb_signal_to_host_p


class ThreadResume(object):
    """
    Describes how to resume a particular thread (or all threads) based on the client's request.
    If thread is -1, then this entry applies to all threads.
    These are passed around as an array.
    """
    RESUME_KIND_MAPPING = {
        "s": ResumeKind.RESUME_STEP,
        "S": ResumeKind.RESUME_STEP,
        "r": ResumeKind.RESUME_STEP,
        "c": ResumeKind.RESUME_CONTINUE,
        "C": ResumeKind.RESUME_CONTINUE,
        "t": ResumeKind.RESUME_STOP
    }

    def __init__(self, thread, kind):
        self.thread = thread
        self.kind = kind
        self.sig = None
        self.step_range_start = 0
        self.step_range_end = 0

    @staticmethod
    def from_vcont(data):
        """
        Create a thread resume object from one chunk of data in vCont packet.
        :param str data:
        :return: A resume action.
        :rtype: ThreadResume
        """

        try:
            kind = ThreadResume.RESUME_KIND_MAPPING[data[0]]
        except KeyError:
            raise VcontActionDecodingError()
        ptid = Ptid.read_ptid(data[data.find(":") + 1:]) if ":" in data else Ptid.minus_one_ptid()
        action = ThreadResume(ptid, kind)
        if data[0] in ("S", "C"):
            sig = int(data[1:3], 16)
            if not gdb_signal_to_host_p(GdbSignal(sig)):
                raise VcontActionDecodingError()
            action.sig = gdb_signal_to_host(GdbSignal(sig))
        if data[0] == "r":
            action.step_range_start = int(data[1:].split(",")[0], 16)
            action.step_range_end = int(data[1:].split(",")[1], 16)
        return action
