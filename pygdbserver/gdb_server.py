from pygdbserver.pygdbserver_exceptions import *


class GdbServer(object):
    def __init__(self, target):
        self.target = target
        self.requests_to_handle_functions_map = {
        }

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
        return "${}#{:X}".format(packet_data, GdbServer.calc_checksum(packet_data))

    def process_packet(self, data):
        """
        Handle receiving packet.
        :param str data: Remote GDB request packet.
        :return: Remote GDB response packet.
        :rtype: str
        """
        packet_data = self.extract_packet_data(data)
        if packet_data[0] in self.requests_to_handle_functions_map:
            response = self.requests_to_handle_functions_map[packet_data[0]](packet_data)
        else:
            response = ""
        return self.construct_packet(response)
