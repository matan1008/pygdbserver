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
        Return true iff the thread with process ID PID is alive.
        :param pid: The process ID.
        :return: Whether the process is alive or not.
        """
        return False

    @abstractmethod
    def resume(self, resume_info):
        """
        Resume the inferior process.
        :param resume_info: List of resume actions.
        """
        pass

    @abstractmethod
    def wait(self, ptid, status, options):
        """
        Wait for the inferior process or thread to change state. Store status through argument status.
        :param ptid: ptid = -1 to wait for any pid to do something,
        PTID(pid,0,0) to wait for any thread of process pid to do something.
        :param status: For storing status.
        :param options: A bit set of options defined as TARGET_W*.
        If options contains TARGET_WNOHANG and there's no child stop to report,
        return is null_ptid/TARGET_WAITKIND_IGNORE.
        :return: Return ptid of child, or -1 in case of error.
        """
        return None

    @abstractmethod
    def fetch_registers(self, regcache, regno):
        """
        Fetch registers from the inferior process.
        :param regcache: Registers cache.
        :param regno: If regno is -1, fetch all registers; otherwise, fetch at least regno.
        """
        pass

    @abstractmethod
    def store_registers(self, regcache, regno):
        """
        Store registers from the inferior process.
        :param regcache: Registers cache.
        :param regno: If regno is -1, store all registers; otherwise, store at least regno.
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
        :return: Returns 0 on success and errno on failure.
        """
        return 1

    @abstractmethod
    def done_accessing_memory(self):
        """
        Undo the effects of prepare_to_access_memory.
        """
        pass

    @abstractmethod
    def read_memory(self, memaddr, myaddr, len):
        """
        Read memory from the inferior process.
        This should generally be called through read_inferior_memory, which handles breakpoint shadowing.
        :param memaddr: Address to read from.
        :param myaddr: Buffer to read into.
        :param len: Number of bytes to read.
        :return: Returns 0 on success and errno on failure.
        """
        return 1

    @abstractmethod
    def write_memory(self, memaddr, myaddr, len):
        """
        Write memory to the inferior process.
        This should generally be called through write_inferior_memory, which handles breakpoint shadowing.
        :param memaddr: Address to write to.
        :param myaddr: Buffer to write.
        :param len: Number of bytes to write.
        :return: Returns 0 on success and errno on failure.
        """
        return 1

    @abstractmethod
    def look_up_symbols(self):
        """
        Query GDB for the values of any symbols we're interested in.
        This function is called whenever we receive a "qSymbols::"
        query, which corresponds to every time more symbols (might)
        become available.  NULL if we aren't interested in any
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
    def read_auxv(self, offset, myaddr, len):
        """
        Read auxiliary vector data from the inferior process.
        :param offset: Offset read from.
        :param myaddr: Buffer to read into.
        :param len: Number of bytes to read.
        :return: Returns 0 on success and errno on failure.
        """
        return 1

    @abstractmethod
    def supports_z_point_type(self, z_type):
        """
        Returns true if GDB Z breakpoint type TYPE is supported, false otherwise.
        :param z_type: The type is coded as follows:
            '0' - software-breakpoint
            '1' - hardware-breakpoint
            '2' - write watchpoint
            '3' - read watchpoint
            '4' - access watchpoint
        :return: True or False
        """
        return False

    @abstractmethod
    def insert_point(self, type_, addr, size, bp):
        """
        Insert a break or watchpoint.
        :param type_: Point's type.
        :param addr: Point's addr.
        :param size: Point's size.
        :param bp: Point's info.
        :return: Returns 0 on success, -1 on failure and 1 on unsupported.
        """
        return 1

    @abstractmethod
    def remove_point(self, type_, addr, size, bp):
        """
        Remove a break or watchpoint.
        :param type_: Point's type.
        :param addr: Point's addr.
        :param size: Point's size.
        :param bp: Point's info.
        :return: Returns 0 on success, -1 on failure and 1 on unsupported.
        """
        return 1

    @abstractmethod
    def stopped_by_sw_breakpoint(self):
        """
        Returns true if the target stopped because it executed a software
        breakpoint instruction, false otherwise.
        :return: True if stopped by sw breakpoint.
        """
        return False

    @abstractmethod
    def supports_stopped_by_sw_breakpoint(self):
        """
        Returns true if the target knows whether a trap was caused by a
        SW breakpoint triggering.
        :return: True if supports trap that caused by sw breakpoint.
        """
        return False

    @abstractmethod
    def stopped_by_hw_breakpoint(self):
        """
        Returns true if the target stopped for a hardware breakpoint.
        :return: True if stopped by hw breakpoint.
        """
        return False

    @abstractmethod
    def supports_stopped_by_hw_breakpoint(self):
        """
        Returns true if the target knows whether a trap was caused by a
        HW breakpoint triggering.
        :return: True if supports trap that caused by hw breakpoint.
        """
        return False

    @abstractmethod
    def supports_hardware_single_step(self):
        """
        Returns true if the target can do hardware single step.
        :return: True is supports hardware single step.
        """
        return False

    @abstractmethod
    def stopped_by_watchpoint(self):
        """
        Returns true if target was stopped due to a watchpoint hit, false otherwise.
        :return: True is stopped by watchpoint.
        """
        return False

    @abstractmethod
    def stopped_data_address(self):
        """
        Returns the address associated with the watchpoint that hit, if any; returns 0 otherwise.
        :return: Address associated with the watchpoint that hit.
        """
        return 0

    @abstractmethod
    def read_offsets(self, text, data):
        """
        Reports the text, data offsets of the executable.
        This is needed for uclinux where the executable is relocated during load time.
        :param text: Executable's text.
        :param data: Executable's data.
        :return: True on success, False otherwise.
        """
        return False
