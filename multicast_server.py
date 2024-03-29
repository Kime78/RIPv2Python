import socket
import struct
import sys
import netifaces
import sys
import signal
import time

def handle_sigint(signum, frame):
    sock.close()
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)
multicast_addr = '224.1.0.9'
server_addr = ('', 10521)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(server_addr)

group = socket.inet_aton(multicast_addr)
mreq = struct.pack('4sL', group, socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

while True:
    time.sleep(2)
    sock.sendto(b"abc", (multicast_addr, 5000))
    # try:
    #     print('Primim de la toti')
    #     data, addr = sock.recvfrom(1024)
    # except:
    #     continue
    # else:
    #     print('Trimitem raspuns')
    #     sock.sendto(b'ack', addr)
    #     print(f'Received {data} from {addr}')