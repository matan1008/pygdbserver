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


class TargetPrepareToAccessMemoryError(TargetError):
    """ Raise when preparing to access memory fails. """

    def __init__(self, errno):
        self.errno = errno


class TargetReadMemoryError(TargetError):
    """ Raise when reading memory fails. """

    def __init__(self, errno):
        self.errno = errno


class TargetWriteMemoryError(TargetError):
    """ Raise when writing memory fails. """

    def __init__(self, errno):
        self.errno = errno


class TargetInsertPointError(TargetError):
    """ Raise when inserting a break or watchpoint fails. """
    pass


class TargetInsertPointNotSupported(TargetError):
    """ Raise when inserting a break or watchpoint is not supported. """
    pass


class TargetRemovePointError(TargetError):
    """ Raise when removing a break or watchpoint fails. """
    pass


class TargetRemovePointNotSupported(TargetError):
    """ Raise when removing a break or watchpoint is not supported. """
    pass


class TargetReadOffsetsError(TargetError):
    """ Raise when reading text and data offsets fails. """
    pass


class TargetGetTlsAddressError(TargetError):
    """ Raise when getting tls address fails. """

    def __init__(self, error_code):
        self.error_code = error_code


class TargetGetTlsAddressNotSupported(TargetError):
    """ Raise when getting tls address is not supported. """
    pass


class TargetQxferSpuError(TargetError):
    """ Raise when reading / writing spufs using qXfer packets fails. """

    def __init__(self, errno):
        self.errno = errno


class TargetQxferOsdataError(TargetError):
    """ Raise when reading / writing OS data using qXfer packets fails. """

    def __init__(self, errno):
        self.errno = errno


class TargetQxferSiginfoError(TargetError):
    """ Raise when reading / writing extra signal info using qXfer packets fails. """

    def __init__(self, errno):
        self.errno = errno
