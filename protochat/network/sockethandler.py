import struct
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class HandshakeFailureException(Exception):
    pass


class SocketNotConnectedException(Exception):
    pass


class AuthenticationFailureException(Exception):
    pass


class SocketHandler:

    MAC_LEN = 16
    IV_LEN = 12
    STREAM_KEY_LEN = 32
    SALT = b'PROTOCHAT HKDF SALT'
    INFO = b'PROTOCHAT HKDF INFO'
    HEADER = b'PROTOCHAT HEADER'
    VERIFY_MSG = b'PROTOCHAT VERIFY'
    CONFIRM_MSG = b'PROTOCHAT CONFIRM'

    def __init__(self, reader, writer):
        self.r = reader
        self.w = writer

        self.chacha = None
        self.nonce = None

    async def perform_handshake(self):
        ## exchange ECDH key
        # create private key
        private_key = ec.generate_private_key(ec.SECP384R1())
        # get associated public key
        public_key = private_key.public_key()
        # send public x and y coordinates
        x = public_key.public_numbers().x
        y = public_key.public_numbers().y
        x_len = len(str(x))
        y_len = len(str(y))
        self.w.write(struct.pack('<i', x_len))
        self.w.write(struct.pack('<i', y_len))
        self.w.write(str(x).encode())
        self.w.write(str(y).encode())
        # get client's public point
        client_pub_length = await self.r.read(4)
        client_pub_length = struct.unpack('<i', client_pub_length[:4])[0]
        client_pub = await self.r.read(client_pub_length)
        client_pub = client_pub.decode('utf-8')
        # bisect concatenated point to get x and y
        idx = (client_pub_length - 2) / 2 + 2
        idx = int(idx)
        client_pub_x = client_pub[2:idx]
        client_pub_y = client_pub[idx:]
        client_pub_x = int(client_pub_x, base=16)
        client_pub_y = int(client_pub_y, base=16)
        # form client's public key
        client_pub_key = ec.EllipticCurvePublicNumbers(
                client_pub_x, client_pub_y, ec.SECP384R1()).public_key()
        # derive shared key from private point and client's public point
        shared_key = private_key.exchange(ec.ECDH(), client_pub_key)

        ## derive stream key
        hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=type(self).STREAM_KEY_LEN,
                salt=type(self).SALT,
                info=type(self).INFO
        )
        # get a suitable key for cipher
        stream_key = hkdf.derive(shared_key)

        ## setup stream cipher
        chacha = ChaCha20Poly1305(stream_key)
        # create and share nonce
        nonce = os.urandom(type(self).IV_LEN)
        self.w.write(nonce)

        ## verify
        msg_ct = await self.r.read(16)
        msg_mac = await self.r.read(type(self).MAC_LEN)
        msg = chacha.decrypt(nonce, msg_ct + msg_mac, type(self).HEADER)
        if msg != type(self).VERIFY_MSG:
            raise HandshakeErrorException("Unable to verify")

        ## confirm
        msg = chacha.encrypt(nonce, type(self).CONFIRM_MSG, type(self).HEADER)
        self.w.write(msg[:-type(self).MAC_LEN])
        self.w.write(msg[-type(self).MAC_LEN:])

        self.chacha = chacha
        self.nonce = nonce

    def send(self, byte_arr):
        if self.chacha is None:
            raise SocketNotConnectedException()
        msg_len = struct.pack('<i', len(byte_arr))
        msg_len = self.chacha.encrypt(self.nonce, msg_len, type(self).HEADER)
        self.w.write(msg_len)
        ct = self.chacha.encrypt(self.nonce, byte_arr, type(self).HEADER)
        self.w.write(ct)

    def send_nohelp(self, byte_arr):
        if self.chacha is None:
            raise SocketNotConnectedException()
        ct = self.chacha.encrypt(self.nonce, byte_arr, type(self).HEADER)
        self.w.write(ct)

    async def receive(self, n):
        if self.chacha is None:
            raise SocketNotConnectedException()
        msg_ct = await self.r.read(n)
        mac = await self.r.read(type(self).MAC_LEN)
        pt = self.chacha.decrypt(self.nonce, msg_ct + mac, type(self).HEADER)
        return pt

