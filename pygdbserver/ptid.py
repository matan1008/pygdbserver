class Ptid(object):
    """
    The Ptid is a collection of the various "ids" necessary for
    identifying the inferior process/thread being debugged.
    """

    def __init__(self, pid, lwp, tid):
        self.pid = pid
        self.lwp = lwp
        self.tid = tid

    def __eq__(self, other):
        return self.pid == other.pid and self.lwp == other.lwp and self.tid == other.tid

    def write_ptid(self, multi_process):
        if multi_process:
            if self.pid < 0:
                buf = "p-{:x}.".format(-self.pid)
            else:
                buf = "p{:x}.".format(self.pid)
        else:
            if self.lwp < 0:
                buf = "-{:x}".format(-self.lwp)
            else:
                buf = "{:x}".format(self.lwp)
        return buf

    def pid_to_ptid(self):
        """
        Make a new ptid from just a pid. This ptid is usually used to
        represent a whole process, including all its lwps/threads.
        """
        return Ptid(self.pid, 0, 0)

    @staticmethod
    def from_pid(pid):
        return Ptid(pid, None, None).pid_to_ptid()

    @staticmethod
    def null_ptid():
        """
        The null or zero ptid, often used to indicate no process.
        """
        return Ptid(0, 0, 0)

    @staticmethod
    def minus_one_ptid():
        """
        The (-1,0,0) ptid, often used to indicate either an error condition
        or a "don't care" condition, i.e, "run all threads."
        """
        return Ptid(-1, 0, 0)

    def __nonzero__(self):
        return self != Ptid.null_ptid()
