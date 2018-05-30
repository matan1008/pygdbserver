# coding=utf-8
from abc import ABCMeta, abstractmethod
from pygdbserver.signals import GdbSignal
from pygdbserver.gdb_enums import ResumeKind
from pygdbserver.thread_resume import ThreadResume


class Target:
    __metaclass__ = ABCMeta

    @abstractmethod
    def create_inferior(self, program, args, add_process, add_thread):
        """
        Start a new process and registers the new process with the process list.
        Adding the process and it's threads should be done with add_process and add_thread.
        It is recommended to fill the process's `tdesc` field (the process is returned from add_process)
        with a `TargetDesc` object.
        :param str program: A path to the program to execute.
        :param list(str) args: An array of arguments, to be passed to the inferior as ``argv''.
        :param function(int, bool) add_process: `add_process(pid, attached)`, The function returns ProcessInfo.
        :param function(Ptid, str) add_thread: `add_thread(ptid, target_data=""])`, The function returns ThreadInfo.
        :return: The new PID on success.
        :rtype: int.
        :raises TargetCreatingInferiorError: If creating process failed.
        """
        raise NotImplementedError()

    @abstractmethod
    def post_create_inferior(self):
        """
        Do additional setup after a new process is created, including exec-wrapper completion.
        """
        raise NotImplementedError()

    @abstractmethod
    def attach(self, pid):
        """
        Attach to a running process.
        :param int pid: The process ID to attach to, specified by the user or a higher layer.
        :raises TargetAttachError: If attaching failed.
        :raises TargetAttachNotSupported: If attaching is unsupported.
        """
        raise NotImplementedError()

    @abstractmethod
    def kill(self, pid):
        """
        Kill inferior PID.
        :param int pid: The process ID to kill.
        :raises TargetKillError: If killing fails.
        """
        raise NotImplementedError()

    @abstractmethod
    def detach(self, pid):
        """
        Detach from inferior PID.
        :param int pid: The process ID to detach from.
        :raises TargetDetachError: If detaching fails.
        """
        raise NotImplementedError()

    @abstractmethod
    def mourn(self, proc):
        """
        The inferior process has died. Do what is right.
        :param ProcessInfo proc: Process to mourn on.
        """
        raise NotImplementedError()

    @abstractmethod
    def join(self, pid):
        """
        Wait for inferior PID to exit.
        :param int pid: The process ID to wait for.
        """
        raise NotImplementedError()

    @abstractmethod
    def thread_alive(self, pid):
        """
        Return true iff the thread with process ID PID is alive.
        :param Ptid pid: The process ID.
        :return: Whether the process is alive or not.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def resume(self, resume_info):
        """
        Resume the inferior process.
        :param list(ThreadResume) resume_info: List of resume actions.
        """
        raise NotImplementedError()

    @abstractmethod
    def wait(self, ptid, status, options):
        """
        Wait for the inferior process or thread to change state. Store status through argument status.
        :param Ptid ptid: ptid = -1 to wait for any pid to do something,
        PTID(pid,0,0) to wait for any thread of process pid to do something.
        :param TargetWaitstatus status: For storing status.
        :param int options: A bit set of options defined as TARGET_W*.
        If options contains TARGET_WNOHANG and there's no child stop to report,
        return is null_ptid/IGNORE.
        :return: Return ptid of child.
        :rtype: Ptid
        :raises TargetWaitError: If waiting fails.
        """
        raise NotImplementedError()

    @abstractmethod
    def fetch_registers(self, regcache, regno):
        """
        Fetch registers from the inferior process.
        :param Regcache regcache: Registers cache.
        :param int regno: If regno is -1, fetch all registers; otherwise, fetch at least regno.
        """
        raise NotImplementedError()

    @abstractmethod
    def store_registers(self, regcache, regno):
        """
        Store registers from the inferior process.
        :param Regcache regcache: Registers cache.
        :param int regno: If regno is -1, store all registers; otherwise, store at least regno.
        """
        raise NotImplementedError()

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
        raise NotImplementedError()

    @abstractmethod
    def done_accessing_memory(self):
        """
        Undo the effects of prepare_to_access_memory.
        """
        raise NotImplementedError()

    @abstractmethod
    def read_memory(self, memaddr, len_):
        """
        Read memory from the inferior process.
        This should generally be called through read_inferior_memory, which handles breakpoint shadowing.
        :param int memaddr: Address to read from.
        :param int len_: Number of bytes to read.
        :return: Data from memory.
        :rtype: str
        :raises TargetReadMemoryError: Raised with errno on failure.
        """
        raise NotImplementedError()

    @abstractmethod
    def write_memory(self, memaddr, myaddr, len_):
        """
        Write memory to the inferior process.
        This should generally be called through write_inferior_memory, which handles breakpoint shadowing.
        :param int memaddr: Address to write to.
        :param str myaddr: Buffer to write.
        :param int len_: Number of bytes to write.
        :raises TargetWriteMemoryError: Raised with errno on failure.
        """
        raise NotImplementedError()

    @abstractmethod
    def look_up_symbols(self):
        """
        Query GDB for the values of any symbols we're interested in.
        This function is called whenever we receive a "qSymbols::"
        query, which corresponds to every time more symbols (might)
        become available. NULL if we aren't interested in any
        symbols.
        """
        raise NotImplementedError()

    @abstractmethod
    def request_interrupt(self):
        """
        Send an interrupt request to the inferior process,
        however is appropriate.
        """
        raise NotImplementedError()

    @abstractmethod
    def read_auxv(self, offset, len_):
        """
        Read auxiliary vector data from the inferior process.
        :param int offset: Offset read from.
        :param int len_: Number of bytes to read.
        :return: Data from memory.
        :rtype: str
        :raises TargetReadMemoryError: Raised with errno on failure.
        """
        raise NotImplementedError()

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
        raise NotImplementedError()

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
        raise NotImplementedError()

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
        raise NotImplementedError()

    @abstractmethod
    def stopped_by_sw_breakpoint(self):
        """
        Returns true if the target stopped because it executed a software
        breakpoint instruction, false otherwise.
        :return: True if stopped by sw breakpoint.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_stopped_by_sw_breakpoint(self):
        """
        Returns true if the target knows whether a trap was caused by a
        SW breakpoint triggering.
        :return: True if supports trap that caused by sw breakpoint.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def stopped_by_hw_breakpoint(self):
        """
        Returns true if the target stopped for a hardware breakpoint.
        :return: True if stopped by hw breakpoint.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_stopped_by_hw_breakpoint(self):
        """
        Returns true if the target knows whether a trap was caused by a
        HW breakpoint triggering.
        :return: True if supports trap that caused by hw breakpoint.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_hardware_single_step(self):
        """
        Returns true if the target can do hardware single step.
        :return: True if supports hardware single step.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def stopped_by_watchpoint(self):
        """
        Returns true if target was stopped due to a watchpoint hit, false otherwise.
        :return: True if stopped by watchpoint.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def stopped_data_address(self):
        """
        Returns the address associated with the watchpoint that hit, if any; returns 0 otherwise.
        :return: Address associated with the watchpoint that hit.
        :rtype: int
        """
        raise NotImplementedError()

    @abstractmethod
    def read_offsets(self):
        """
        Reports the text, data offsets of the executable.
        This is needed for uclinux where the executable is relocated during load time.
        :return: A tuple of executable's text and executable's data, (text, data).
        :rtype: tuple(int, int)
        :raises TargetReadOffsetsError: On reading failure.
        """
        raise NotImplementedError()

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
        raise NotImplementedError()

    @abstractmethod
    def qxfer_spu(self, annex, writebuf, offset, len_):
        """
        Read/Write from/to spufs using qXfer packets.
        :param str annex: Memory's annex, of the form id/name.
        :param str writebuf: Writing buffer.
        :param int offset: Reading / writing offset.
        :param int len_: Reading / writing size.
        :return: Returns reading buffer on reading, undefined on writing.
        :rtype: str
        :raises TargetQxferSpuError: On reading / writing error.
        """
        raise NotImplementedError()

    @abstractmethod
    def hostio_last_error(self):
        """
        Return an hostio error packet representing the last hostio.
        :return: Last hostio.
        :rtype: str
        """
        raise NotImplementedError()

    @abstractmethod
    def qxfer_osdata(self, annex, writebuf, offset, len_):
        """
        Read/Write OS data using qXfer packets.
        :param str annex: Memory's annex, of the form id/name.
        :param str writebuf: Writing buffer.
        :param int offset: Reading / writing offset.
        :param int len_: Reading / writing size.
        :return: Returns reading buffer on reading, undefined on writing.
        :rtype: str
        :raises TargetQxferOsdataError: On reading / writing error.
        """
        raise NotImplementedError()

    @abstractmethod
    def qxfer_siginfo(self, annex, writebuf, offset, len_):
        """
        Read/Write extra signal info.
        :param str annex: Memory's annex, of the form id/name.
        :param str writebuf: Writing buffer.
        :param int offset: Reading / writing offset.
        :param int len_: Reading / writing size.
        :return: Returns reading buffer on reading, undefined on writing.
        :rtype: str
        :raises TargetQxferSiginfoError: On reading / writing error.
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_non_stop(self):
        """
        Returns true if target supports non stop mode, false otherwise.
        :return: If target supports non stop
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def async_events(self, enable):
        """
        Enables async target events.
        :param bool enable: True for enabling async target events, False for disabling.
        :return: Returns the previous enable state.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def start_non_stop(self, non_stop):
        """
        Switch to non-stop or all-stop mode.
        :param bool non_stop: True for switching to non-stop mode, False for all-stop.
        :raises TargetStartNonStopError: On switching error.
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_multi_process(self):
        """
        Returns true if the target supports multi-process debugging.
        :return: True if supports multi-process debugging.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_fork_events(self):
        """
        Returns true if fork events are supported.
        :return: True if supports fork events.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_vfork_events(self):
        """
        Returns true if vfork events are supported.
        :return: True if supports vfork events.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_exec_events(self):
        """
        Returns true if exec events are supported.
        :return: True if supports exec events.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def handle_new_gdb_connection(self):
        """
        Allows target to re-initialize connection-specific settings.
        """
        raise NotImplementedError()

    @abstractmethod
    def handle_monitor_command(self, command):
        """
        If not None, target-specific routine to process monitor command.
        :param str command: Monitor command.
        :return: True if handled, or False to perform default processing.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def core_of_thread(self, ptid):
        """
        Returns the core given a thread.
        :param Ptid ptid: Thread's ptid.
        :return: Core of thread.
        :rtype: int
        :raises TargetUnknownCoreOfThreadError: if core is not known.
        """
        raise NotImplementedError()

    @abstractmethod
    def read_loadmap(self, annex, offset, len_):
        """
        Read loadmaps.
        :param str annex: Memory's annex, of the form id/name.
        :param int offset: Reading offset.
        :param int len_: Reading size.
        :return: Returns reading buffer.
        :rtype: str
        :raises TargetReadLoadmapError: On reading error.
        """
        raise NotImplementedError()

    @abstractmethod
    def process_qsupported(self, features):
        """
        Target specific qSupported support.
        :param list(str) features: List of features
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_tracepoints(self):
        """
        Returns true if the target supports tracepoints.
        :return: True if the target supports tracepoints.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def read_pc(self, regcache):
        """
        Read PC from regcache.
        :param Regcache regcache: Regcache to read from.
        :return: PC.
        :rtype: int
        """
        raise NotImplementedError()

    @abstractmethod
    def write_pc(self, regcache, pc):
        """
        Write pc to regcache.
        :param Regcache regcache: Regcache to write pc to.
        :param int pc: pc to write.
        """
        raise NotImplementedError()

    @abstractmethod
    def thread_stopped(self, thread):
        """
        Return true if thread is known to be stopped now.
        :param ThreadInfo thread: Thread to check.
        :return: If thread is stopped.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def get_tib_address(self, ptid):
        """
        Read Thread Information Block address.
        :param Ptid ptid: Thread's id.
        :return: Thread's information block address.
        :rtype: int
        :raises TargetGetTibAddressError: Raised with error code on failure.
        """
        raise NotImplementedError()

    @abstractmethod
    def pause_all(self, freeze):
        """
        Pause all threads. There can be nested calls to pause_all, so a freeze counter
        should be maintained.
        :param bool freeze: If freeze, arrange for any resume attempt to
        be ignored until an unpause_all call unfreezes threads again.
        """
        raise NotImplementedError()

    @abstractmethod
    def unpause_all(self, unfreeze):
        """
        Unpause all threads.  Threads that hadn't been resumed by the
        client should be left stopped.  Basically a pause/unpause call
        pair should not end up resuming threads that were stopped before
        the pause call.
        :param bool unfreeze: Opposite of `pause_all` freeze param
        """
        raise NotImplementedError()

    @abstractmethod
    def stabilize_threads(self):
        """
        Stabilize all threads. That is, force them out of jump pads.
        """
        raise NotImplementedError()

    @abstractmethod
    def install_fast_tracepoint_jump_pad(self, tpoint, tpaddr, collector, lockaddr, orig_size, jump_entry,
                                         jjump_pad_insn):
        """
        Install a fast tracepoint jump pad.
        :param int tpoint: The address of the tracepoint internal object as used by the IPA agent.
        :param int tpaddr: The address of tracepoint.
        :param int collector: Address of the function the jump pad redirects to.
        :param int lockaddr: The address of the jump pad lock object.
        :param int orig_size: The size in bytes of the instruction at `tpaddr`.
        :param int jump_entry: Points to the address of the jump pad entry.
        :param str jjump_pad_insn: A buffer containing a copy of the instruction at `tpaddr`.
        :return: A tuple from the format:
        (jump_entry, trampoline, trampoline_size, adjusted_insn_addr, adjusted_insn_addr_end), where:
            - *jump_entry*: The address past the end of the created jump pad.
            - *trampoline*: If a trampoline is created by the function, trampoline's address, else -1.
            - *trampoline_size*: If a trampoline is created by the function, trampoline's size, else -1.
            - *adjusted_insn_addr*: Start of address range where the instruction at `tpaddr` was relocated to.
            - *adjusted_insn_addr_end*: End of address range where the instruction at `tpaddr` was relocated to.
        :rtype: tuple(int, int, int, int, int)
        :raises TargetInstallFastTracepointJumpPadError: Raised with error message in err if an error occurs
        """
        raise NotImplementedError()

    @abstractmethod
    def emit_ops(self):
        """
        Return the bytecode operations vector for the current inferior.
        :return: Bytecode operations vector.
        :rtype: EmitOps.
        :raises TargetEmitOpsNotSupported: If bytecode compilation is not supported.
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_disable_randomization(self):
        """
        Returns true if the target supports disabling randomization.
        :return: True if supports disable randomization.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def get_min_fast_tracepoint_insn_len(self):
        """
        Return the minimum length of an instruction that can be safely overwritten for use as a fast tracepoint.
        :return: Minimum length.
        :rtype: int
        """
        raise NotImplementedError()

    @abstractmethod
    def qxfer_libraries_svr4(self, annex, writebuf, offset, len_):
        """
        Read solib info on SVR4 platforms.
        :param str annex: Memory's annex, of the form id/name.
        :param str writebuf: Writing buffer, for consistency purpose only.
        :param int offset: Reading offset.
        :param int len_: Reading size.
        :return: Returns reading buffer on reading.
        :rtype: str
        :raises TargetQxferLibrariesSvr4Error: On reading error.
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_agent(self):
        """
        Return true if target supports debugging agent.
        :return: True if supports agent.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_btrace(self, btrace_format):
        """
        Check whether the target supports branch tracing.
        :param BtraceFormat btrace_format: Branch tracing format.
        :return: True if supports btrace.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def enable_btrace(self, ptid, conf):
        """
        Enable branch tracing for `ptid` based on `conf` and allocate a branch trace
        target information struct for reading and for disabling branch trace.
        :param Ptid ptid: Thread's id.
        :param BtraceConfig conf: Btrace configuration.
        :return: Btrace info.
        :rtype: BtraceTargetInfo
        """
        raise NotImplementedError()

    @abstractmethod
    def disable_btrace(self, tinfo):
        """
        Disable branch tracing.
        :param BtraceTargetInfo tinfo: Branch tracing info.
        :raises TargetDisableBtraceError: In failure.
        """
        raise NotImplementedError()

    @abstractmethod
    def read_btrace(self, tinfo, read_type):
        """
        Read branch trace data.
        :param BtraceTargetInfo tinfo: Branch trace to read.
        :param BtraceReadType read_type: Read type (all, new, delta).
        :return: Branch trace's data.
        :rtype: str
        :raises TargetReadBtraceError: On reading failure.
        """
        raise NotImplementedError()

    @abstractmethod
    def read_btrace_conf(self, tinfo):
        """
        Read the branch trace configuration.
        :param BtraceTargetInfo tinfo: Branch trace to read.
        :return: Branch trace's configuration.
        :rtype: str
        :raises TargetReadBtraceConfigurationError: On reading failure.
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_range_stepping(self):
        """
        Return true if target supports range stepping.
        :return: True if supports range stepping.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def pid_to_exec_file(self, pid):
        """
        Return the full absolute name of the executable file that was run to create the process `pid`.
        :param int pid: Process id.
        :return: A pointer to a character string containing the pathname.
        :rtype: str
        :raises TargetPidToExecFileError: If the executable file cannot be determined.
        """
        raise NotImplementedError()

    @abstractmethod
    def multifs_open(self, pid, filename, flags, mode):
        """
        Multiple-filesystem-aware open. Like open(2), but operating in the filesystem as it appears to process PID.
        :param int pid: Process id.
        :param str filename: Like open(2).
        :param int flags: Like open(2).
        :param int mode: Like open(2).
        :return: Like open(2).
        :rtype: int
        :raises NotImplementedError: On systems where all processes share a common filesystem.
        """
        raise NotImplementedError()

    @abstractmethod
    def multifs_unlink(self, pid, filename):
        """
        Multiple-filesystem-aware unlink. Like unlink(2), but operates in the filesystem as it appears to process `pid`.
        :param int pid: Process id.
        :param str filename: Like unlink(2).
        :return: Like unlink(2).
        :rtype: int
        :raises NotImplementedError: On systems where all processes share a common filesystem.
        """
        raise NotImplementedError()

    @abstractmethod
    def multifs_readlink(self, pid, filename):
        """
        Multiple-filesystem-aware readlink. Like readlink(2),
        but operating in the filesystem as it appears to process `pid`.
        :param int pid:
        :param str filename:
        :return: Contents of the symbolic link.
        :rtype: str
        :raises TargetReadlinkError: On readlink internal errors, raised with errno.
        :raises NotImplementedError: On systems where all processes share a common filesystem.
        """
        raise NotImplementedError()

    @abstractmethod
    def breakpoint_kind_from_pc(self, pcptr):
        """
        Return the breakpoint kind for this target based on PC.
        The `pcptr` is adjusted to the real memory location in case a flag
        (e.g., the Thumb bit on ARM) was present in the PC.
        :param int pcptr: Adjusted PC.
        :return: Breakpoint kind.
        :rtype: int
        """
        raise NotImplementedError()

    @abstractmethod
    def sw_breakpoint_from_kind(self, kind):
        """
        Return the software breakpoint from `kind`.
        :param int kind: Can have target specific meaning like the Z0 kind parameter.
        :return: Software breakpoint (as written in memory).
        :rtype: str
        """
        raise NotImplementedError()

    @abstractmethod
    def thread_name(self, ptid):
        """
        Return the thread's name.
        :param Ptid ptid: Thread's id.
        :return: Thread's name.
        :rtype: str
        :raises TargetThreadNameError: If the target is unable to determine it.
        """
        raise NotImplementedError()

    @abstractmethod
    def breakpoint_kind_from_current_state(self, pcptr):
        """
        Return the breakpoint kind for this target based on the current
        processor state (e.g. the current instruction mode on ARM) and the
        PC. The `pcptr` is adjusted to the real memory location in case a flag
        (e.g., the Thumb bit on ARM) is present in the PC.
        :param int pcptr: Adjusted PC.
        :return: Breakpoint kind.
        :rtype: int
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_software_single_step(self):
        """
        Returns true if the target can software single step.
        :return: True if supports software single stepping.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def supports_catch_syscall(self):
        """
        Return true if the target supports catch syscall, false otherwise.
        :return: True if supports catch syscall.
        :rtype: bool
        """
        raise NotImplementedError()

    @abstractmethod
    def get_ipa_tdesc_idx(self):
        """
        Return tdesc index for IPA.
        :return: Target description index.
        :rtype: int
        """
        raise NotImplementedError()

    def continue_no_signal(self, ptid):
        """
        Request to continue with signal 0.
        :param Ptid ptid: Ptid to continue.
        """
        self.resume([ThreadResume(ptid, ResumeKind.RESUME_CONTINUE, GdbSignal.GDB_SIGNAL_0)])
