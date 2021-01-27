import asyncio
import sys

from protochat import client_handler

if len(sys.argv) != 2:
    print('Usage: python3 main.py <bind address> <port>')
    sys.exit(1)

bind_addr = sys.argv[1]
port = int(sys.argv[2])

loop = asyncio.get_event_loop()
coro = asyncio.start_server(client_handler, bind_addr, port)
server = loop.run_until_complete(coro)
print('Server has started')
loop.run_forever()

