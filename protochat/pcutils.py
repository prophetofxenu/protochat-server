import binascii
import os

def hex_id(length):
    h = binascii.b2a_hex(os.urandom(length))
    h = str(h)
    return h[2:-1]

