from .network.sockethandler import SocketHandler

async def handle_client(reader, writer):
    sock = SocketHandler(reader, writer)
    await sock.perform_handshake()

