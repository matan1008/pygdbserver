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
