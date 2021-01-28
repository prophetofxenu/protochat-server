import asyncio
import sys

from protochat.clienthandler import handle_client

if len(sys.argv) != 3:
    print('Usage: python3 main.py <bind address> <port>')
    sys.exit(1)

bind_addr = sys.argv[1]
port = int(sys.argv[2])

loop = asyncio.get_event_loop()
coro = asyncio.start_server(handle_client, bind_addr, port)
server = loop.run_until_complete(coro)
print('Server has started')
try:
    loop.run_forever()
except KeyboardInterrupt:
    print('\nShutting down')

