# coding=utf-8
from pygdbserver.thread_info import ThreadInfo
from pygdbserver.process_info import ProcessInfo
from pygdbserver.target_waitstatus import TargetWaitStatus
from pygdbserver.gdb_enums import *
from pygdbserver.pygdbserver_exceptions import *


class GdbServer(object):
    def __init__(self, target):
        self.target = target
        self.requests_to_handle_functions_map = {
            "!": self.handle_extend_protocol,
            "?": self.handle_status,
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

    @staticmethod
    def write_ok():
        """ Return positive response """
        return "OK"

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

    def find_inferior_by_ptid(self, ptid, inferiors_list):
        try:
            return filter(lambda inf: inf.id == ptid, inferiors_list)[0]
        except IndexError:
            return None

    def find_process(self, ptid):
        """ Find a process_info by matching `ptid`. """
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

    def prepare_resume_reply(self, ptid, status):
        raise NotImplementedError("yet")

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
            if self.last_status.kind not in (
                    TargetWaitkind.TARGET_WAITKIND_IGNORE, TargetWaitkind.TARGET_WAITKIND_EXITED,
                    TargetWaitkind.TARGET_WAITKIND_SIGNALLED):
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
                assert thread.last_status.kind != TargetWaitkind.TARGET_WAITKIND_IGNORE
                return self.prepare_resume_reply(thread.id, thread.last_status)
            else:
                return "W00"

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
