class PyGdbServerException(Exception):
    """ Domain exception for pygdbserver. """
    pass


class TargetError(PyGdbServerException):
    """ For any exception that might be raised from the target. """
    pass


class TargetCreatingInferiorError(TargetError):
    """ Raise when creating a new process fails. """
    pass


class TargetAttachError(TargetError):
    """ Raise when attaching to a running process fails. """
    pass


class TargetAttachNotSupported(TargetError):
    """ Raise when attaching to a running process is not supported. """
    pass


class TargetKillError(TargetError):
    """ Raise when killing a process fails. """
    pass


class TargetDetachError(TargetError):
    """ Raise when detaching from a process fails. """
    pass


class TargetWaitError(TargetError):
    """ Raise when waiting to a process fails. """
    pass
