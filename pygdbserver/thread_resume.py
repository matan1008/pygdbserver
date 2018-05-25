# coding=utf-8
""" Module for ThreadResume class. """


class ThreadResume(object):
    """
    Describes how to resume a particular thread (or all threads) based on the client's request.
    If thread is -1, then this entry applies to all threads.
    These are passed around as an array.
    """

    def __init__(self, thread, kind, sig):
        self.thread = thread
        self.kind = kind
        self.sig = sig
        self.step_range_start = 0
        self.step_range_end = 0
