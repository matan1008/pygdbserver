class PyGdbServerException(Exception):
    """ Domain exception for pygdbserver. """
    pass


class TargetCreatingInferiorError(Exception):
    """ Raise when creating a new process fails. """
    pass
