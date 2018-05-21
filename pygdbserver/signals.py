# coding=utf-8
import os
import signal
from enum import Enum
from pygdbserver.pygdbserver_exceptions import GdbUnknownSignal


def get_signals_data(def_path):
    """ Prepare all signals data from a signals.def file. """
    with open(def_path) as fd:
        signals_defs = fd.readlines()
    signals_defs = [x.split(", ") for x in signals_defs]
    for sig in signals_defs:
        sig[1] = int(sig[1])
    return zip(*signals_defs)


symbols, constants, names, strings = get_signals_data(os.path.join("pygdbserver", "signals.def"))
GdbSignal = Enum("GdbSignal", dict(zip(symbols, constants)))


def gdb_signal_to_symbol_string(sig):
    """ Return the enum symbol name of SIG as a string, to use in debug output."""
    return sig.name


def gdb_signal_to_string(sig):
    """ Return the string for a signal. """
    return strings[symbols.index(sig.name)]


def gdb_signal_to_name(sig):
    """ Return the name (SIGHUP, etc.) for a signal. """
    return names[symbols.index(sig.name)]


def do_gdb_signal_to_host(oursig):
    """ Convert a `oursig` (an enum gdb_signal) to the form used by the target operating system. """
    if oursig == GdbSignal.GDB_SIGNAL_0:
        return 0
    elif oursig == GdbSignal.GDB_SIGNAL_INT:
        return signal.SIGINT
    elif oursig == GdbSignal.GDB_SIGNAL_ILL:
        return signal.SIGILL
    elif oursig == GdbSignal.GDB_SIGNAL_ABRT:
        return signal.SIGABRT
    elif oursig == GdbSignal.GDB_SIGNAL_FPE:
        return signal.SIGFPE
    elif oursig == GdbSignal.GDB_SIGNAL_SEGV:
        return signal.SIGSEGV
    elif oursig == GdbSignal.GDB_SIGNAL_TERM:
        return signal.SIGTERM
    elif hasattr(signal, "SIGHUP") and oursig == GdbSignal.GDB_SIGNAL_HUP:
        return signal.SIGHUP
    elif hasattr(signal, "SIGQUIT") and oursig == GdbSignal.GDB_SIGNAL_QUIT:
        return signal.SIGQUIT
    elif hasattr(signal, "SIGTRAP") and oursig == GdbSignal.GDB_SIGNAL_TRAP:
        return signal.SIGTRAP
    elif hasattr(signal, "SIGEMT") and oursig == GdbSignal.GDB_SIGNAL_EMT:
        return signal.SIGEMT
    elif hasattr(signal, "SIGKILL") and oursig == GdbSignal.GDB_SIGNAL_KILL:
        return signal.SIGKILL
    elif hasattr(signal, "SIGBUS") and oursig == GdbSignal.GDB_SIGNAL_BUS:
        return signal.SIGBUS
    elif hasattr(signal, "SIGSYS") and oursig == GdbSignal.GDB_SIGNAL_SYS:
        return signal.SIGSYS
    elif hasattr(signal, "SIGPIPE") and oursig == GdbSignal.GDB_SIGNAL_PIPE:
        return signal.SIGPIPE
    elif hasattr(signal, "SIGALRM") and oursig == GdbSignal.GDB_SIGNAL_ALRM:
        return signal.SIGALRM
    elif hasattr(signal, "SIGUSR1") and oursig == GdbSignal.GDB_SIGNAL_USR1:
        return signal.SIGUSR1
    elif hasattr(signal, "SIGUSR2") and oursig == GdbSignal.GDB_SIGNAL_USR2:
        return signal.SIGUSR2
    elif (hasattr(signal, "SIGCHLD") or hasattr(signal, "SIGCLD")) and oursig == GdbSignal.GDB_SIGNAL_CHLD:
        if hasattr(signal, "SIGCHLD"):
            return signal.SIGCHLD
        else:
            return signal.SIGCLD
    elif hasattr(signal, "SIGPWR") and oursig == GdbSignal.GDB_SIGNAL_PWR:
        return signal.SIGPWR
    elif hasattr(signal, "SIGWINCH") and oursig == GdbSignal.GDB_SIGNAL_WINCH:
        return signal.SIGWINCH
    elif hasattr(signal, "SIGURG") and oursig == GdbSignal.GDB_SIGNAL_URG:
        return signal.SIGURG
    elif hasattr(signal, "SIGIO") and oursig == GdbSignal.GDB_SIGNAL_IO:
        return signal.SIGIO
    elif hasattr(signal, "SIGPOLL") and oursig == GdbSignal.GDB_SIGNAL_POLL:
        return signal.SIGPOLL
    else:
        raise GdbUnknownSignal("Unknwon signal")


def gdb_signal_to_host_p(oursig):
    """ Predicate to gdb_signal_to_host(). """
    try:
        do_gdb_signal_to_host(oursig)
        return True
    except GdbUnknownSignal:
        return False


def gdb_signal_to_host(oursig):
    """ Convert between host signal numbers and enum gdb_signal's. """
    try:
        targ_signo = do_gdb_signal_to_host(oursig)
    except GdbUnknownSignal:
        targ_signo = 0
    return targ_signo
