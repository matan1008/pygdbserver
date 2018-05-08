class PyGdbServerException(Exception):
    """ Domain exception for pygdbserver. """
    pass


class TargetCreatingInferiorError(PyGdbServerException):
    """ Raise when creating a new process fails. """
    pass


class TargetAttachError(PyGdbServerException):
    """ Raise when attaching to a running process fails. """
    pass


class TargetAttachNotSupported(PyGdbServerException):
    """ Raise when attaching to a running process is not supported. """
    pass
