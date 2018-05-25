# coding=utf-8
import os
import sys
import signal
import atexit
import logging
from pygdbserver.ptid import Ptid
from pygdbserver.regcache import Regcache
from pygdbserver.thread_info import ThreadInfo
from pygdbserver.process_info import ProcessInfo
from pygdbserver.target_waitstatus import TargetWaitStatus
from pygdbserver.signals import GdbSignal, gdb_signal_to_host, gdb_signal_to_name
from pygdbserver.gdb_enums import *
from pygdbserver.pygdbserver_exceptions import *


class GdbServer(object):
    def __init__(self, target, logger=None):
        if logger is None:
            logging.basicConfig()
            self.logger = logging.getLogger("gdbserver")
        else:
            self.logger = logger
        self.target = target
        self.requests_to_handle_functions_map = {
            "!": self.handle_extend_protocol,
            "?": self.handle_status,
            "v": self.handle_v_requests,
        }

        self.all_processes = []
        self.all_threads = []
        self.extended_protocol = False
        self.non_stop = False
        self.last_status = TargetWaitStatus()
        self.last_ptid = None
        self.cont_thread = None
        self.general_thread = None
        self.current_thread = None
        self.saved_thread = None
        self.disable_packet_v_cont = False
        self.v_cont_supported = True
        self.multi_process = False
        self.report_fork_events = False
        self.report_vfork_events = False
        self.report_exec_events = False
        self.report_thread_events = False
        self.swbreak_feature = False
        self.hwbreak_feature = False
        self.using_threads = False
        self.disable_packet_t_thread = True
        self.dll_changed = False
        self.program_argv = []
        self.wrapper_argv = []
        self.server_waiting = False

    @staticmethod
    def write_ok():
        """ Return positive response """
        return "OK"

    @staticmethod
    def write_enn():
        """ Return negative response """
        return "E01"

    @staticmethod
    def calc_checksum(st):
        """
        Calculate checksum.
        :param str st: Buffer to calculate checksum on.
        :return: Checksum.
        :rtype: int
        """
        return sum(ord(c) for c in st) % 256

    @staticmethod
    def extract_packet_data(packet):
        """
        Validate checksum and extract packet data from a remote gdb protocol packet.
        :param str packet: A remote gdb protocol packet, from the form `$packet-data#checksum`.
        :return: Packet's data.
        :rtype: str
        :raises InvalidPacketError: Either when packet structure is invalid or checksum is wrong.
        """
        if packet[0] != "$" or packet[-3] != "#":
            raise InvalidPacketError("Packet doesn't contain '$' or '#'")
        if GdbServer.calc_checksum(packet[1:-3]) != int(packet[-2:], 16):
            raise InvalidPacketError("Wrong checksum")
        return packet[1:-3]

    @staticmethod
    def construct_packet(packet_data):
        """
        Calculate data's checksum and construct a valid remote gdb packet.
        :param str packet_data: Packet's data.
        :return: GDB packet.
        :rtype: str
        """
        return "${}#{:02X}".format(packet_data, GdbServer.calc_checksum(packet_data))

    @staticmethod
    def find_inferior_by_ptid(ptid, inferiors_list):
        try:
            return filter(lambda inf: inf.id == ptid, inferiors_list)[0]
        except IndexError:
            return None

    def find_process(self, ptid):
        """
        Find a process_info by matching `ptid`.
        :param Ptid ptid:
        :rtype: ProcessInfo
        """
        return self.find_inferior_by_ptid(ptid, self.all_processes)

    def find_thread(self, ptid):
        """ Find a thread_info by matching `ptid`. """
        return self.find_inferior_by_ptid(ptid, self.all_threads)

    def set_desired_thread(self, use_general):
        if use_general:
            self.current_thread = self.find_thread(self.general_thread)
        else:
            self.current_thread = self.find_thread(self.cont_thread)
        return self.current_thread is not None

    def target_running(self):
        """
        Check if any threads are running.
        :return: If any threads are running.
        :rtype: bool
        """
        return bool(self.all_threads)

    def current_process(self):
        """
        Get the current process from the current thread.
        :return: Current process.
        :rtype: ProcessInfo
        """
        assert self.current_thread is not None
        return self.find_process(self.current_thread.id.pid_to_ptid())

    def get_thread_regcache(self, thread, fetch):
        """
        Get thread's regcache.
        :param ThreadInfo thread:
        :param bool fetch:
        :return:
        :rtype: Regcache
        """
        if thread.regcache_data is None:
            proc = self.find_process(thread.id.pid_to_ptid())
            assert proc.tdesc is not None and proc.tdesc.registers_size != 0
            thread.regcache_data = Regcache(proc.tdesc)
        if fetch and not thread.regcache_data.registers_valid:
            saved_thread = self.current_thread
            self.current_thread = thread
            thread.regcache_data.invalidate_registers()
            self.target.fetch_registers(thread.regcache_data, -1)
            self.current_thread = saved_thread
            thread.regcache_data.registers_valid = True
        return thread.regcache_data

    def prepare_resume_reply(self, ptid, status):
        """
        Prepare a resume reply.
        :param Ptid ptid:
        :param TargetWaitStatus status:
        :return: Resume reply.
        :rtype: str
        """
        self.logger.debug("Writing resume reply for %s:%d\n", str(ptid), status.kind)
        if status.kind in (
                TargetWaitkind.STOPPED, TargetWaitkind.FORKED, TargetWaitkind.VFORKED, TargetWaitkind.VFORK_DONE,
                TargetWaitkind.EXECD, TargetWaitkind.THREAD_CREATED, TargetWaitkind.SYSCALL_ENTRY,
                TargetWaitkind.SYSCALL_RETURN):
            if (status.kind is TargetWaitkind.FORKED and self.report_fork_events) or (
                            status.kind is TargetWaitkind.VFORKED and self.report_vfork_events):
                event = "fork" if status.kind is TargetWaitkind.FORKED else "vfork"
                resp = "T{:02x}{}:{};".format(GdbSignal.GDB_SIGNAL_TRAP, event,
                                              status.related_pid.write_ptid(self.multi_process))
            elif status.kind is TargetWaitkind.VFORK_DONE and self.report_vfork_events:
                resp = "T{:02x}vforkdone:;".format(GdbSignal.GDB_SIGNAL_TRAP)
            elif status.kind is TargetWaitkind.EXECD and self.report_exec_events:
                resp = "T{:02x}{}:{};".format(GdbSignal.GDB_SIGNAL_TRAP, "exec", status.execd_pathname.encode("hex"))
                status.execd_pathname = None
            elif status.kind is TargetWaitkind.THREAD_CREATED and self.report_thread_events:
                resp = "T{:02x}create:;".format(GdbSignal.GDB_SIGNAL_TRAP)
            elif status.kind in (TargetWaitkind.SYSCALL_ENTRY, TargetWaitkind.SYSCALL_RETURN):
                event = "syscall_entry" if status.kind is TargetWaitkind.SYSCALL_ENTRY else "syscall_return"
                resp = "T{:02x}{}:{:x};".format(GdbSignal.GDB_SIGNAL_TRAP, event, status.syscall_number)
            else:
                resp = "T{:02x}".format(status.sig)
            saved_thread = self.current_thread
            self.current_thread = self.find_thread(ptid)
            expedite_regs = self.current_process().tdesc.expedite_regs if self.current_process() is not None else []
            regcache = self.get_thread_regcache(self.current_thread, True)
            if self.target.stopped_by_watchpoint():
                resp += "watch:{:08x};".format(self.target.stopped_data_address())
            elif self.swbreak_feature and self.target.stopped_by_sw_breakpoint():
                resp += "swbreak:;"
            elif self.hwbreak_feature and self.target.stopped_by_hw_breakpoint():
                resp += "hwbreak:;"
            resp += "".join(map(regcache.out_reg_name, expedite_regs))
            if self.using_threads and not self.disable_packet_t_thread:
                if self.general_thread != ptid:
                    if not self.non_stop:
                        self.general_thread = ptid
                    resp += "thread:{};".format(ptid.write_ptid(self.multi_process))
                    try:
                        resp += "core:{:x};".format(self.target.core_of_thread(ptid))
                    except TargetUnknownCoreOfThreadError:
                        pass
            if self.dll_changed:
                resp += "library:;"
                self.dll_changed = False
            self.current_thread = saved_thread
        elif status.kind is TargetWaitkind.EXITED:
            resp = "W{:x};process:{:x}".format(status.integer, ptid.pid) if self.multi_process else "W{:02x}".format(
                status.integer)
        elif status.kind is TargetWaitkind.SIGNALLED:
            resp = "X{:x};process:{:x}".format(status.sig, ptid.pid) if self.multi_process else "X{:02x}".format(
                status.sig)
        elif status.kind is TargetWaitkind.THREAD_EXITED:
            resp = "w{:x};{}".format(status.integer, ptid.write_ptid(self.multi_process))
        elif status.kind is TargetWaitkind.NO_RESUMED:
            resp = "N"
        else:
            raise UnhandledWaitkindError()
        return resp

    def handle_extend_protocol(self, data):
        """ Extend protocol """
        self.extended_protocol = True
        return self.write_ok()

    def handle_status(self, data):
        """ Status handler for the '?' packet. """
        map(ProcessInfo.gdb_reattached_process, self.all_processes)
        if self.non_stop:
            raise NotImplementedError()
        else:
            self.target.pause_all(False)
            self.target.stabilize_threads()
            map(ThreadInfo.gdb_wants_thread_stopped, self.all_threads)
            map(ThreadInfo.set_pending_status, self.all_threads)
            thread = None
            # Prefer the last thread that reported an event to GDB (even if that was a GDB_SIGNAL_TRAP).
            if self.last_status.kind not in (TargetWaitkind.IGNORE, TargetWaitkind.EXITED, TargetWaitkind.SIGNALLED):
                thread = self.find_thread(self.last_ptid)
            # If the last event thread is not found for some reason,
            # look for some other thread that might have an event to report.
            if thread is None:
                pending_threads = filter(ThreadInfo.is_status_pending, self.all_threads)
                thread = pending_threads[0] if pending_threads else None
            # If we're still out of luck, simply pick the first thread in the thread list.
            if thread is None:
                thread = self.all_threads[0] if self.all_threads else None
            if thread is not None:
                thread.status_pending_p = False
                self.general_thread = thread.id
                self.set_desired_thread(True)
                assert thread.last_status.kind != TargetWaitkind.IGNORE
                return self.prepare_resume_reply(thread.id, thread.last_status)
            else:
                return "W00"

    def my_wait(self, ptid, our_status, options, connected_wait):
        """
        Wait for process.
        :param Ptid ptid:
        :param TargetWaitStatus our_status:
        :param int options:
        :param bool connected_wait:
        :return: Ptid of child
        :rtype: Ptid
        """
        if connected_wait:
            self.server_waiting = True
        ret = self.target.wait(ptid, our_status, options)
        if our_status.kind is TargetWaitkind.LOADED:
            our_status.kind = TargetWaitkind.STOPPED
        if our_status.kind is TargetWaitkind.EXITED:
            self.logger.error("\nChild exited with status %d\n", our_status.integer)
        elif our_status.kind is TargetWaitkind.SIGNALLED:
            self.logger.error("\nChild terminated with signal = 0x%x (%s)\n", gdb_signal_to_host(our_status.sig),
                              gdb_signal_to_name(our_status.sig))
        if connected_wait:
            self.server_waiting = False
        return ret

    def start_inferior(self, argv):
        """
        Create an inferior.
        :param list(str) argv: Inferior's arguments vector.
        :return: new inferior's pid.
        :rtype: int
        """
        new_argv = self.wrapper_argv + argv
        map(lambda i, arg: self.logger.debug("new_argv[%d] = \"%s\"\n", i, arg), enumerate(new_argv))
        if hasattr(signal, "SIGTTOU") and hasattr(signal, "SIGTTIN"):
            signal.signal(signal.SIGTTOU, signal.SIG_DFL)
            signal.signal(signal.SIGTTIN, signal.SIG_DFL)
        signal_pid = self.target.create_inferior(new_argv[0], new_argv)
        self.logger.error("Process %s created; pid = %ld\n", argv[0], signal_pid)
        if hasattr(signal, "SIGTTOU") and hasattr(signal, "SIGTTIN"):
            signal.signal(signal.SIGTTOU, signal.SIG_IGN)
            signal.signal(signal.SIGTTIN, signal.SIG_IGN)
            old_foreground_pgrp = os.tcgetpgrp(sys.stderr.fileno())
            os.tcsetpgrp(sys.stderr.fileno(), signal_pid)
            atexit.register(os.tcsetpgrp, sys.stderr.fileno(), old_foreground_pgrp)
        if self.wrapper_argv:
            self.last_ptid = self.my_wait(Ptid.from_pid(signal_pid), self.last_status, 0, False)
            condition = self.last_status.kind is TargetWaitkind.STOPPED
            while condition:
                self.target.continue_no_signal(Ptid.from_pid(signal_pid))
                self.last_ptid = self.my_wait(Ptid.from_pid(signal_pid), self.last_status, 0, False)
                if self.last_status.kind is not TargetWaitkind.STOPPED:
                    break
                self.current_thread.last_resume_kind = ResumeKind.RESUME_STOP
                self.current_thread.last_status = self.last_status
                condition = self.last_status.sig != GdbSignal.GDB_SIGNAL_TRAP
            self.target.post_create_inferior()
            return signal_pid
        self.last_ptid = self.my_wait(Ptid.from_pid(signal_pid), self.last_status, 0, False)
        if self.last_status.kind not in (TargetWaitkind.EXITED, TargetWaitkind.SIGNALLED):
            self.target.post_create_inferior()
            self.current_thread.last_resume_kind = ResumeKind.RESUME_STOP
            self.current_thread.last_status = self.last_status
        else:
            self.target.mourn(self.find_process(self.last_ptid.pid_to_ptid()))
        return signal_pid

    def handle_v_run(self, data):
        """ Run a new program. """
        new_argv = data[len("vRun;"):].split(";")
        if new_argv[0] == "":
            if not self.program_argv or self.program_argv[0] == "":
                return self.write_enn()
            new_argv[0] = self.program_argv[0]
        self.program_argv = new_argv
        self.start_inferior(self.program_argv)
        if self.last_status.kind is TargetWaitkind.STOPPED:
            resp = self.prepare_resume_reply(self.last_ptid, self.last_status)
            if self.non_stop:
                self.general_thread = self.last_ptid
            return resp
        else:
            return self.write_enn()

    def handle_v_requests(self, data):
        """
        Handle all of the extended 'v' packets.
        :param str data: Remote GDB request packet.
        """
        if not self.disable_packet_v_cont:
            if data == "vCtrlC":
                self.target.request_interrupt()
                return self.write_ok()
            elif data.startswith("vCont;"):
                pass
            elif data.startswith("vCont?"):
                res = "vCont;c;C;t"
                if self.target.supports_hardware_single_step() or \
                        self.target.supports_software_single_step() or not self.v_cont_supported:
                    res += ";s;S"
                if self.target.supports_range_stepping():
                    res += ";r"
                return res
        if data.startswith("vFile:"):
            pass
        if data.startswith("vAttach;"):
            pass
        if data.startswith("vRun;"):
            if (not self.extended_protocol or not self.multi_process) and self.target_running():
                self.logger.info("Already debugging a process\n")
                return self.write_enn()
            return self.handle_v_run(data)

    def process_packet(self, data):
        """
        Handle receiving packet.
        :param str data: Remote GDB request packet.
        :return: Remote GDB response packet.
        :rtype: str
        """
        if data in ("+", "-"):
            return ""
        packet_data = self.extract_packet_data(data)
        if packet_data[0] in self.requests_to_handle_functions_map:
            response = self.requests_to_handle_functions_map[packet_data[0]](packet_data)
        else:
            response = ""
        return self.construct_packet(response)
