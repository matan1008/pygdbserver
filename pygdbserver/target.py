from abc import ABCMeta, abstractmethod


class Target:
    __metaclass__ = ABCMeta

    @abstractmethod
    def create_inferior(self, program, args):
        """
        Start a new process and registers the new process with the process list.
        :param program: A path to the program to execute.
        :param args: An array of arguments, to be passed to the inferior as ``argv''.
        :return: The new PID on success, -1 on failure.
        """
        return -1

    @abstractmethod
    def post_create_inferior(self):
        """
        Do additional setup after a new process is created, including exec-wrapper completion.
        """
        pass

    @abstractmethod
    def attach(self, pid):
        """
        Attach to a running process.
        :param pid: The process ID to attach to, specified by the user or a higher layer.
        :return: Returns -1 if attaching is unsupported, 0 on success, and calls error() otherwise.
        """
        return -1

    @abstractmethod
    def kill(self, pid):
        """
        Kill inferior PID.
        :param pid: The process ID to kill.
        :return: Return -1 on failure, and 0 on success.
        """
        return -1

    @abstractmethod
    def detach(self, pid):
        """
        Detach from inferior PID.
        :param pid: The process ID to detach from.
        :return: Return -1 on failure, and 0 on success.
        """
        return -1

    @abstractmethod
    def mourn(self, proc):
        """
        The inferior process has died. Do what is right.
        :param proc: Process to mourn on.
        """
        pass

    @abstractmethod
    def join(self, pid):
        """
        Wait for inferior PID to exit.
        :param pid: The process ID to wait for.
        """
        pass

    @abstractmethod
    def thread_alive(self, pid):
        """
        Return true if the thread with process ID PID is alive.
        :param pid: The process ID.
        :return: Whether the process ia alive or not.
        """
        return False
