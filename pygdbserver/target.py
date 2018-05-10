from abc import ABCMeta, abstractmethod
from pygdbserver.pygdbserver_exceptions import *


class Target:
    __metaclass__ = ABCMeta

    @abstractmethod
    def create_inferior(self, program, args):
        """
        Start a new process and registers the new process with the process list.
        :param str program: A path to the program to execute.
        :param list args: An array of arguments, to be passed to the inferior as ``argv''.
        :return: The new PID on success.
        :rtype: int.
        :raises TargetCreatingInferiorError: If creating process failed.
        """
        raise TargetCreatingInferiorError()

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
        :param int pid: The process ID to attach to, specified by the user or a higher layer.
        :raises TargetAttachError: If attaching failed.
        :raises TargetAttachNotSupported: If attaching is unsupported.
        """
        raise TargetAttachNotSupported()

    @abstractmethod
    def kill(self, pid):
        """
        Kill inferior PID.
        :param int pid: The process ID to kill.
        :raises TargetKillError: If killing fails.
        """
        raise TargetKillError()

    @abstractmethod
    def detach(self, pid):
        """
        Detach from inferior PID.
        :param int pid: The process ID to detach from.
        :raises TargetDetachError: If detaching fails.
        """
        raise TargetDetachError()

    @abstractmethod
    def mourn(self, proc):
        """
        The inferior process has died. Do what is right.
        :param ProcessInfo proc: Process to mourn on.
        """
        pass

    @abstractmethod
    def join(self, pid):
        """
        Wait for inferior PID to exit.
        :param int pid: The process ID to wait for.
        """
        pass

    @abstractmethod
    def thread_alive(self, pid):
        """
        Return true iff the thread with process ID PID is alive.
        :param Ptid pid: The process ID.
        :return: Whether the process is alive or not.
        :rtype: bool
        """
        return False

    @abstractmethod
    def resume(self, resume_info):
        """
        Resume the inferior process.
        :param list resume_info: List of resume actions.
        """
        pass

    @abstractmethod
    def wait(self, ptid, status, options):
        """
        Wait for the inferior process or thread to change state. Store status through argument status.
        :param Ptid ptid: ptid = -1 to wait for any pid to do something,
        PTID(pid,0,0) to wait for any thread of process pid to do something.
        :param TargetWaitstatus status: For storing status.
        :param int options: A bit set of options defined as TARGET_W*.
        If options contains TARGET_WNOHANG and there's no child stop to report,
        return is null_ptid/TARGET_WAITKIND_IGNORE.
        :return: Return ptid of child.
        :rtype: Ptid
        :raises TargetWaitError: If waiting fails.
        """
        raise TargetWaitError()

    @abstractmethod
    def fetch_registers(self, regcache, regno):
        """
        Fetch registers from the inferior process.
        :param Regcache regcache: Registers cache.
        :param int regno: If regno is -1, fetch all registers; otherwise, fetch at least regno.
        """
        pass

    @abstractmethod
    def store_registers(self, regcache, regno):
        """
        Store registers from the inferior process.
        :param Regcache regcache: Registers cache.
        :param int regno: If regno is -1, store all registers; otherwise, store at least regno.
        """
        pass

    @abstractmethod
    def prepare_to_access_memory(self):
        """
        Prepare to read or write memory from the inferior process.
        Targets use this to do what is necessary to get the state of the
        inferior such that it is possible to access memory.

        This should generally only be called from client facing routines,
        such as gdb_read_memory/gdb_write_memory, or the GDB breakpoint
        insertion routine.
        :raises TargetPrepareToAccessMemoryError: Raised with errno on failure.
        """
        raise TargetPrepareToAccessMemoryError(0)

    @abstractmethod
    def done_accessing_memory(self):
        """
        Undo the effects of prepare_to_access_memory.
        """
        pass

    @abstractmethod
    def read_memory(self, memaddr, len):
        """
        Read memory from the inferior process.
        This should generally be called through read_inferior_memory, which handles breakpoint shadowing.
        :param int memaddr: Address to read from.
        :param int len: Number of bytes to read.
        :return: Data from memory.
        :rtype: str
        :raises TargetReadMemoryError: Raised with errno on failure.
        """
        raise TargetReadMemoryError(0)

    @abstractmethod
    def write_memory(self, memaddr, myaddr, len):
        """
        Write memory to the inferior process.
        This should generally be called through write_inferior_memory, which handles breakpoint shadowing.
        :param int memaddr: Address to write to.
        :param str myaddr: Buffer to write.
        :param int len: Number of bytes to write.
        :raises TargetWriteMemoryError: Raised with errno on failure.
        """
        raise TargetWriteMemoryError(0)

    @abstractmethod
    def look_up_symbols(self):
        """
        Query GDB for the values of any symbols we're interested in.
        This function is called whenever we receive a "qSymbols::"
        query, which corresponds to every time more symbols (might)
        become available. NULL if we aren't interested in any
        symbols.
        """
        pass

    @abstractmethod
    def request_interrupt(self):
        """
        Send an interrupt request to the inferior process,
        however is appropriate.
        """
        pass

    @abstractmethod
    def read_auxv(self, offset, len):
        """
        Read auxiliary vector data from the inferior process.
        :param int offset: Offset read from.
        :param int len: Number of bytes to read.
        :return: Data from memory.
        :rtype: str
        :raises TargetReadMemoryError: Raised with errno on failure.
        """
        raise TargetReadMemoryError(0)

    @abstractmethod
    def supports_z_point_type(self, z_type):
        """
        Returns true if GDB Z breakpoint type z_type is supported, false otherwise.
        :param str z_type: The type is coded as follows:
            '0' - software-breakpoint
            '1' - hardware-breakpoint
            '2' - write watchpoint
            '3' - read watchpoint
            '4' - access watchpoint
        :return: If GDB Z breakpoint type is supported.
        :rtype: bool
        """
        return False

    @abstractmethod
    def insert_point(self, type_, addr, size, bp):
        """
        Insert a break or watchpoint.
        :param RawBkptType type_: Point's type.
        :param int addr: Point's addr.
        :param int size: Point's size.
        :param RawBreakpoint bp: Point's info.
        :raises TargetInsertPointError: On inserting failure.
        :raises TargetInsertPointNotSupported: If inserting is unsupported.
        """
        raise TargetInsertPointNotSupported()

    @abstractmethod
    def remove_point(self, type_, addr, size, bp):
        """
        Remove a break or watchpoint.
        :param RawBkptType type_: Point's type.
        :param int addr: Point's addr.
        :param int size: Point's size.
        :param RawBreakpoint bp: Point's info.
        :raises TargetRemovePointError: On removing failure.
        :raises TargetRemovePointNotSupported: If removing is unsupported.
        """
        raise TargetRemovePointNotSupported()

    @abstractmethod
    def stopped_by_sw_breakpoint(self):
        """
        Returns true if the target stopped because it executed a software
        breakpoint instruction, false otherwise.
        :return: True if stopped by sw breakpoint.
        :rtype: bool
        """
        return False

    @abstractmethod
    def supports_stopped_by_sw_breakpoint(self):
        """
        Returns true if the target knows whether a trap was caused by a
        SW breakpoint triggering.
        :return: True if supports trap that caused by sw breakpoint.
        :rtype: bool
        """
        return False

    @abstractmethod
    def stopped_by_hw_breakpoint(self):
        """
        Returns true if the target stopped for a hardware breakpoint.
        :return: True if stopped by hw breakpoint.
        :rtype: bool
        """
        return False

    @abstractmethod
    def supports_stopped_by_hw_breakpoint(self):
        """
        Returns true if the target knows whether a trap was caused by a
        HW breakpoint triggering.
        :return: True if supports trap that caused by hw breakpoint.
        :rtype: bool
        """
        return False

    @abstractmethod
    def supports_hardware_single_step(self):
        """
        Returns true if the target can do hardware single step.
        :return: True if supports hardware single step.
        :rtype: bool
        """
        return False

    @abstractmethod
    def stopped_by_watchpoint(self):
        """
        Returns true if target was stopped due to a watchpoint hit, false otherwise.
        :return: True if stopped by watchpoint.
        :rtype: bool
        """
        return False

    @abstractmethod
    def stopped_data_address(self):
        """
        Returns the address associated with the watchpoint that hit, if any; returns 0 otherwise.
        :return: Address associated with the watchpoint that hit.
        :rtype: int
        """
        return 0

    @abstractmethod
    def read_offsets(self):
        """
        Reports the text, data offsets of the executable.
        This is needed for uclinux where the executable is relocated during load time.
        :return: A tuple of executable's text and executable's data, (text, data).
        :rtype: tuple(int, int)
        :raises TargetReadOffsetsError: On reading failure.
        """
        raise TargetReadOffsetsError()

    @abstractmethod
    def get_tls_address(self, thread, offset, load_module):
        """
        Fetch the address associated with a specific thread local storage
        area, determined by the specified thread, offset, and load_module.
        :param ThreadInfo thread: Address's thread.
        :param int offset: Address's offset.
        :param int load_module: Address's load_module.
        :return: Thread's local storage address.
        :rtype: int
        :raises TargetGetTlsAddressError: Raised with error code on failure.
        :raises TargetGetTlsAddressNotSupported: If fetching the address is unsupported.
        """
        raise TargetGetTlsAddressNotSupported()

    @abstractmethod
    def qxfer_spu(self, annex, writebuf, offset, len):
        """
        Read/Write from/to spufs using qXfer packets.
        :param str annex: Memory's annex, of the form id/name.
        :param str writebuf: Writing buffer.
        :param int offset: Reading / writing offset.
        :param int len: Reading / writing size.
        :return: Returns reading buffer on reading, undefined on writing.
        :rtype: str
        :raises TargetQxferSpuError: On reading / writing error.
        """
        raise TargetQxferSpuError(0)

    @abstractmethod
    def hostio_last_error(self):
        """
        Return an hostio error packet representing the last hostio.
        :return: Last hostio.
        :rtype: str
        """
        return ""

    @abstractmethod
    def qxfer_osdata(self, annex, writebuf, offset, len):
        """
        Read/Write OS data using qXfer packets.
        :param str annex: Memory's annex, of the form id/name.
        :param str writebuf: Writing buffer.
        :param int offset: Reading / writing offset.
        :param int len: Reading / writing size.
        :return: Returns reading buffer on reading, undefined on writing.
        :rtype: str
        :raises TargetQxferOsdataError: On reading / writing error.
        """
        raise TargetQxferOsdataError(0)

    @abstractmethod
    def qxfer_siginfo(self, annex, writebuf, offset, len):
        """
        Read/Write extra signal info.
        :param str annex: Memory's annex, of the form id/name.
        :param str writebuf: Writing buffer.
        :param int offset: Reading / writing offset.
        :param int len: Reading / writing size.
        :return: Returns reading buffer on reading, undefined on writing.
        :rtype: str
        :raises TargetQxferSiginfoError: On reading / writing error.
        """
        raise TargetQxferSiginfoError(0)

    @abstractmethod
    def supports_non_stop(self):
        """
        Returns true if target supports non stop mode, false otherwise.
        :return: If target supports non stop
        :rtype: bool
        """
        return False

    @abstractmethod
    def async(self, enable):
        """
        Enables async target events.
        :param bool enable: True for enabling async target events, False for disabling.
        :return: Returns the previous enable state.
        :rtype: bool
        """
        return False

    @abstractmethod
    def start_non_stop(self, non_stop):
        """
        Switch to non-stop or all-stop mode.
        :param bool non_stop: True for switching to non-stop mode, False for all-stop.
        :raises TargetStartNonStopError: On switching error.
        """
        raise TargetStartNonStopError()

    @abstractmethod
    def supports_multi_process(self):
        """
        Returns true if the target supports multi-process debugging.
        :return: True if supports multi-process debugging.
        :rtype: bool
        """
        return False

    @abstractmethod
    def supports_fork_events(self):
        """
        Returns true if fork events are supported.
        :return: True if supports fork events.
        :rtype: bool
        """
        return False

    @abstractmethod
    def supports_vfork_events(self):
        """
        Returns true if vfork events are supported.
        :return: True if supports vfork events.
        :rtype: bool
        """
        return False

    @abstractmethod
    def supports_exec_events(self):
        """
        Returns true if exec events are supported.
        :return: True if supports exec events.
        :rtype: bool
        """
        return False

    @abstractmethod
    def handle_new_gdb_connection(self):
        """
        Allows target to re-initialize connection-specific settings.
        """
        pass

    @abstractmethod
    def handle_monitor_command(self, command):
        """
        If not None, target-specific routine to process monitor command.
        :param str command: Monitor command.
        :return: True if handled, or False to perform default processing.
        :rtype: bool
        """
        return False

    @abstractmethod
    def core_of_thread(self, ptid):
        """
        Returns the core given a thread.
        :param Ptid ptid: Thread's ptid.
        :return: Core of thread.
        :rtype: int
        :raises TargetUnknownCoreOfThreadError: if core is not known.
        """
        return TargetUnknownCoreOfThreadError()

    @abstractmethod
    def read_loadmap(self, annex, offset, len):
        """
        Read loadmaps.
        :param str annex: Memory's annex, of the form id/name.
        :param int offset: Reading offset.
        :param int len: Reading size.
        :return: Returns reading buffer.
        :rtype: str
        :raises TargetReadLoadmapError: On reading error.
        """
        raise TargetReadLoadmapError(0)

    @abstractmethod
    def process_qsupported(self, features):
        """
        Target specific qSupported support.
        :param list(str) features: List of features
        """
        pass

    @abstractmethod
    def supports_tracepoints(self):
        """
        Returns true if the target supports tracepoints.
        :return: True if the target supports tracepoints.
        :rtype: bool
        """
        return False

    @abstractmethod
    def read_pc(self, regcache):
        """
        Read PC from regcache.
        :param Regcache regcache: Regcache to read from.
        :return: PC.
        :rtype: int
        """
        return 0

    @abstractmethod
    def write_pc(self, regcache, pc):
        """
        Write pc to regcache.
        :param Regcache regcache: Regcache to write pc to.
        :param int pc: pc to write.
        """
        pass

    @abstractmethod
    def thread_stopped(self, thread):
        """
        Return true if thread is known to be stopped now.
        :param ThreadInfo thread: Thread to check.
        :return: If thread is stopped.
        :rtype: bool
        """
        return True

    @abstractmethod
    def get_tib_address(self, ptid):
        """
        Read Thread Information Block address.
        :param Ptid ptid: Thread's id.
        :return: Thread's information block address.
        :rtype: int
        :raises TargetGetTibAddressError: Raised with error code on failure.
        """
        raise TargetGetTibAddressError(0)

    @abstractmethod
    def pause_all(self, freeze):
        """
        Pause all threads. There can be nested calls to pause_all, so a freeze counter
        should be maintained.
        :param bool freeze: If freeze, arrange for any resume attempt to
        be ignored until an unpause_all call unfreezes threads again.
        """
        pass

    @abstractmethod
    def unpause_all(self, unfreeze):
        """
        Unpause all threads.  Threads that hadn't been resumed by the
        client should be left stopped.  Basically a pause/unpause call
        pair should not end up resuming threads that were stopped before
        the pause call.
        :param bool unfreeze: Opposite of `pause_all` freeze param
        """
        pass
