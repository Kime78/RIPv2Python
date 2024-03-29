import socket
import struct
import sys
import signal

def handle_sigint(signum, frame):
    sock.close()
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

message = b'hewwo <3'
multicast_group = ('224.1.0.9', 10520)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.2)

ttl = struct.pack('b', 1)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

sock.sendto(message, multicast_group)
while True:
    try:
        data, server = sock.recvfrom(16)
    except:
        continue
    else:    
        print(f'Received {data} from {server}')
        
        sock.sendto(bytes(input('Mesaj: '), encoding='ascii'), multicast_group)