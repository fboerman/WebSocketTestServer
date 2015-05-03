__author__ = 'williewonka'
__version__ = str(1.0)
#a simple websocket server that echo's back received messages. uses no encryption

import socketserver
import threading
import hashlib
import base64

class ThreadedServerHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # addr = self.request.getpeername()[0]
        self.data = self.request.recv(1024)
        request = str(self.data, "utf-8")
        print("request:\n" + request)
        self.HandShake(request)
        while True:
            try:
                data = self.parse_frame()
                if data == "":
                    continue
                print("\nmessage received from " + self.origin + ": " + str(data, "utf-8"))
                print("\n")
                self.request.sendall(self.create_frame(str(data, "utf-8")))
                print("\n")
            except:
                print("\nClient from " + self.origin + " disconnected")
                return

    def HandShake(self, request):
        specificationGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        websocketkey = ""
        protocol = ""
        for line in request.split("\r\n"):
            if "Sec-WebSocket-Key:" in line:
                websocketkey = line.split(" ")[1]
            elif "Sec-WebSocket-Protocol" in line:
                protocol = line.split(":")[1].strip().split(",")[0].strip()
            elif "Origin" in line:
                self.origin = line.split(":")[0]

        print("websocketkey: " + websocketkey + "\n")
        fullKey = hashlib.sha1(websocketkey.encode("utf-8") + specificationGUID.encode("utf-8")).digest()
        acceptKey = base64.b64encode(fullKey)
        print("acceptKey: " + str(acceptKey, "utf-8") + "\n")
        if protocol != "":
            handshake = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: " + protocol + "\r\nSec-WebSocket-Accept: " + str(acceptKey, "utf-8") + "\r\n\r\n"
        else:
            handshake = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + str(acceptKey, "utf-8") + "\r\n\r\n"
        print(handshake.strip("\n"))
        self.request.send(bytes(handshake, "utf-8"))



    def create_frame(self, data):
        # pack bytes for sending to client
        frame_head = bytearray(2)

        # set final fragment
        frame_head[0] = self.set_bit(frame_head[0], 7)

        # set opcode 1 = text
        frame_head[0] = self.set_bit(frame_head[0], 0)

        # payload length
        assert len(data) < 126, "haven't implemented that yet"
        frame_head[1] = len(data)

        # add data
        frame = frame_head + data.encode('utf-8')
        print("frame crafted for message " + data + ":")
        print(list(hex(b) for b in frame))
        return frame

    def is_bit_set(self, int_type, offset):
        mask = 1 << offset
        return not 0 == (int_type & mask)

    def set_bit(self, int_type, offset):
        return int_type | (1 << offset)

    def bytes_to_int(self, data):
        # note big-endian is the standard network byte order
        return int.from_bytes(data, byteorder='big')

    def parse_frame(self):
        """receive data from client"""
        s = self.request
        # read the first two bytes
        frame_head = s.recv(2)

        # very first bit indicates if this is the final fragment
        print("final fragment: ", self.is_bit_set(frame_head[0], 7))

        # bits 4-7 are the opcode (0x01 -> text)
        print("opcode: ", frame_head[0] & 0x0f)

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
        print('Payload is {} bytes'.format(payload_length))

        #masking key
        #All frames sent from the client to the server are masked by a
        #32-bit nounce value that is contained within the frame

        masking_key = s.recv(4)
        print("mask: ", masking_key, self.bytes_to_int(masking_key))

        # finally get the payload data:
        masked_data_in = s.recv(payload_length)
        data = bytearray(payload_length)

        # The ith byte is the XOR of byte i of the data with
        # masking_key[i % 4]
        for i, b in enumerate(masked_data_in):
            data[i] = b ^ masking_key[i%4]
        return data

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

HOST = "localhost"
PORT = 600
server = ThreadedTCPServer((HOST, PORT), ThreadedServerHandler)
server_thread = threading.Thread(target=server.serve_forever)
server_thread.daemon = True
server_thread.start()
print("server started, waiting for connections...")

while True:
    pass