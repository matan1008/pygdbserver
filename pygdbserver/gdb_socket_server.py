import SocketServer
from pygdbserver.gdb_server import GdbServer


class GdbServerRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(1024)
            self.request.sendall(self.server.gdb_server.process_packet(data))


class GdbSocketServer(SocketServer.TCPServer):
    def __init__(self, target, server_address):
        SocketServer.TCPServer.__init__(self, server_address, GdbServerRequestHandler)
        self.gdb_server = GdbServer(target)
