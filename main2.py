from __future__ import absolute_import
__author__ = u'williewonka'
__version__ = unicode(1.0)
#a simple websocket server that echo's back received messages. uses no encryption

import SocketServer
import threading
import hashlib
import base64

class ThreadedServerHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        # addr = self.request.getpeername()[0]
        self.data = self.request.recv(1024)
        request = unicode(self.data, u"utf-8")
        print u"request:\n" + request
        self.HandShake(request)
        while True:
            try:
                data = self.parse_frame()
                if data == u"":
                    continue
                print u"\nmessage received from " + self.origin + u": " + unicode(data, u"utf-8")
                print u"\n"
                self.request.sendall(self.create_frame(unicode(data, u"utf-8")))
                print u"\n"
            except:
                print u"\nClient from " + self.origin + u" disconnected"
                return

    def HandShake(self, request):
        specificationGUID = u"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        websocketkey = u""
        protocol = u""
        for line in request.split(u"\r\n"):
            if u"Sec-WebSocket-Key:" in line:
                websocketkey = line.split(u" ")[1]
            elif u"Sec-WebSocket-Protocol" in line:
                protocol = line.split(u":")[1].strip().split(u",")[0].strip()
            elif u"Origin" in line:
                self.origin = line.split(u":")[0]

        print u"websocketkey: " + websocketkey + u"\n"
        fullKey = hashlib.sha1(websocketkey.encode(u"utf-8") + specificationGUID.encode(u"utf-8")).digest()
        acceptKey = base64.b64encode(fullKey)
        print u"acceptKey: " + unicode(acceptKey, u"utf-8") + u"\n"
        if protocol != u"":
            handshake = u"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: " + protocol + u"\r\nSec-WebSocket-Accept: " + unicode(acceptKey, u"utf-8") + u"\r\n\r\n"
        else:
            handshake = u"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + unicode(acceptKey, u"utf-8") + u"\r\n\r\n"
        print handshake.strip(u"\n")
        self.request.send(str(handshake).encode("utf-8"))



    def create_frame(self, data):
        # pack bytes for sending to client
        frame_head = bytearray(2)

        # set final fragment
        frame_head[0] = self.set_bit(frame_head[0], 7)

        # set opcode 1 = text
        frame_head[0] = self.set_bit(frame_head[0], 0)

        # payload length
        assert len(data) < 126, u"haven't implemented that yet"
        frame_head[1] = len(data)

        # add data
        frame = frame_head + data.encode(u'utf-8')
        print u"frame crafted for message " + data + u":"
        print list(hex(b) for b in frame)
        return frame

    def is_bit_set(self, int_type, offset):
        mask = 1 << offset
        return not 0 == (int_type & mask)

    def set_bit(self, int_type, offset):
        return int_type | (1 << offset)

    def bytes_to_int(self, data):
        # note big-endian is the standard network byte order
        return int.from_bytes(data, byteorder=u'big')

    def parse_frame(self):
        u"""receive data from client"""
        s = self.request
        # read the first two bytes
        frame_head = s.recv(2)

        # very first bit indicates if this is the final fragment
        print u"final fragment: ", self.is_bit_set(frame_head[0], 7)

        # bits 4-7 are the opcode (0x01 -> text)
        print u"opcode: ", frame_head[0] & 0x0f

        # mask bit, from client will ALWAYS be 1
        assert self.is_bit_set(frame_head[1], 7)

        # length of payload
        # 7 bits, or 7 bits + 16 bits, or 7 bits + 64 bits
        payload_length = frame_head[1] & 0x7F
        if payload_length == 126:
            raw = s.recv(2)
            payload_length = self.bytes_to_int(raw)
        elif payload_length == 127:
            raw = s.recv(8)
            payload_length = self.bytes_to_int(raw)
        print u'Payload is {} bytes'.format(payload_length)

        #masking key
        #All frames sent from the client to the server are masked by a
        #32-bit nounce value that is contained within the frame

        masking_key = s.recv(4)
        print u"mask: ", masking_key, self.bytes_to_int(masking_key)

        # finally get the payload data:
        masked_data_in = s.recv(payload_length)
        data = bytearray(payload_length)

        # The ith byte is the XOR of byte i of the data with
        # masking_key[i % 4]
        for i, b in enumerate(masked_data_in):
            data[i] = b ^ masking_key[i%4]
        return data

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

HOST = u"localhost"
PORT = 600
server = ThreadedTCPServer((HOST, PORT), ThreadedServerHandler)
server_thread = threading.Thread(target=server.serve_forever)
server_thread.daemon = True
server_thread.start()
print u"server started, waiting for connections..."

while True:
    pass