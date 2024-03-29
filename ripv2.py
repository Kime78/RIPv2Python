import socket
import threading
import time
import netifaces as ni
import struct

MAX_BUFFER_SIZE = 520
lock = threading.Lock()

hostnames = {
    '192.168.122.111': "debian1 enp1s0",
    '192.168.100.243': "debian1 enp7s0 inet12",
    '192.168.101.193': "debian1 enp8s0 inet13",
    
    '192.168.122.33': "debian2 enp1s0",
    '192.168.100.69': "debian2 enp7s0 inet12",
    '192.168.102.133': "debian2 enp8s0 inet24",
    
    '192.168.122.118': "debian3 enp1s0",
    '192.168.101.217': "debian3 enp7s0 inet13",
    '192.168.103.131': "debian3 enp8s0 inet35",
    
    '192.168.122.23': "debian4 enp1s0",
    '192.168.102.197': "debian4 enp7s0 inet24",
    '192.168.104.251': "debian4 enp8s0 inet45",
    
    '192.168.122.21': "debian5 enp1s0",
    '192.168.103.174': "debian5 enp7s0 inet35",
    '192.168.104.253': "debian5 enp8s0 inet45",
    
}
class RIPEntry:
    def __init__(self, target_ip, next_ip, distance, subnet_mask) -> None:
        self.target_ip = target_ip
        self.next_ip = next_ip
        self.distance = distance
        self.subnet_mask = subnet_mask
     
        self.timeout_timer = threading.Timer(interval=100, function=self.on_timeout)
        #self.timeout_timer.start()
        #print("Entry created?")
            
    def start_timeout(self):
        self.timeout_timer.start()
        
    def to_string(self):
        string =  f"<Target ip: {self.target_ip} next hop: {self.next_ip} distance: {self.distance}>"
        if self.target_ip in hostnames:
            return (string + " " + hostnames[self.target_ip])
        return string
    
    def on_timeout(self):
        #print(f"RIP entry for {self} has timed out")
        self.timeout_timer.cancel()

    def to_bytes(self):
        result = [0x00, 0x02, 0x00, 0x00]
        for w in self.target_ip.split("."):
            result.append(int(w))
        for w in self.subnet_mask.split("."):
            result.append(int(w))
        for w in self.next_ip.split("."):
            result.append(int(w))
        result.append(0x00)
        result.append(0x00)
        result.append(0x00)
        result.append(self.distance)
        return bytes(result)

class RIPEntriesList(threading.Thread):
    def __init__(self) -> None:
        super().__init__()
        self.name = "RIPEntriesList thread"
        self.entries = {}

    def add(self, entry: RIPEntry):
        if entry is not self.entries or self.entries[entry.target_ip].distance <= entry.distance:
            self.entries[entry.target_ip] = entry

    def run(self):
        global lock
        while True:
            lock.acquire()
            copy_entries = self.entries.copy()
            for entry in copy_entries.values():
                if entry.timeout_timer.is_alive() == False:
                    del self.entries[entry.target_ip]
            lock.release()
            
    def to_string(self):
        global lock
        result = []
        lock.acquire()
        for entry in self.entries.values():
            result.append(entry.to_string())
        lock.release()
        return result

def create_rip_message(type, entries): 
   result = [type, 0x02, 0x00, 0x00] 
   for entry in entries.values(): 
       for w in entry.to_bytes(): 
           result.append(w) 
   return bytes(result) 

def parse_ripv2_packet(packet: bytes):
    if packet[1] != 0x02 or packet[2] != 0x00 or packet[3] != 0x00:
        return None

    entries = []
    start_index = 5
    while start_index < len(packet):
        afi = packet[start_index]

        route_tag = packet[start_index + 1]

        network_address = ''
        for i in range(3, 7):
            network_address += str(packet[start_index + i]) + '.'
        network_address = network_address[:len(network_address) - 1]
        
        subnet_mask = ''
        for i in range(7, 11):
            subnet_mask += str(packet[start_index + i]) + '.'
        subnet_mask = subnet_mask[:len(subnet_mask) - 1]
        
        next_hop_address = ''
        for i in range(11, 15):
            next_hop_address += str(packet[start_index + i]) + '.'
        next_hop_address = next_hop_address[:len(next_hop_address) - 1]
        
        metric = packet[start_index + 18]

        entry = RIPEntry(network_address, next_hop_address, metric, subnet_mask)
        entries.append(entry)

        start_index += 20

    return entries

def sendRequests(message, interface):
    while True:
        try:
            with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP) as sock:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2) # Set multicast TTL to 2 to limit the scope
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reusing address for multicast
                if interface not in ni.interfaces():
                    raise Exception('Interface does not exist')
                addr = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
                sock.bind((addr, 10520))
                # Send RIPv2 message to multicast address
                sock.sendto(message, ('224.0.0.10', 10520))
        except:
            pass
        finally:
            time.sleep(4)

def listenRequestPackets(interface):
    addrs = []
    for iface in ni.interfaces():
        if ni.AF_INET in ni.ifaddresses(iface):
            address = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
            addrs.append(address)
    while True:
        try:
            with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP) as sock:
                if interface not in ni.interfaces():
                    raise Exception('Interface does not exist')
                addr = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
                group = socket.inet_aton('224.0.0.10')
                mreq = struct.pack('4s4s', group, socket.inet_aton(addr))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2) # Set multicast TTL to 2 to limit the scope
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reusing address for multicast
                sock.bind(('0.0.0.0', 10520))
               
                # Receive RIPv2 message from multicast address
                data, addr = sock.recvfrom(MAX_BUFFER_SIZE)

                if addr[0] not in addrs:
                    #print('Received RIPv2 message from IP address on interface:', interface, ':', addr, data)
                    sendRecievePacket(ni.ifaddresses(interface)[ni.AF_INET][0]['addr'], addr)
        except:
            pass
        
def sendRecievePacket(iface_addr, address):
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP) as sock:
        global rip_entries
        entries = rip_entries.entries
        entries[iface_addr] = RIPEntry(iface_addr, iface_addr, 1, '255.255.255.0')
        message = create_rip_message(2, entries)
        sock.sendto(message, address)
        #print(f'sent recieve packet {message} to {address}')

def listenRecievePackets(interface):
    global rip_entries
    global lock
    while True:
        with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP) as sock:
            try:
                address = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
                addrs = []
                for iface in ni.interfaces():
                    if iface not in ['enp1s0']:
                        if ni.AF_INET in ni.ifaddresses(iface):
                            address = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
                            addrs.append(address)
                    
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((address, 10520))
                data, address = sock.recvfrom(MAX_BUFFER_SIZE)
                data, address = sock.recvfrom(MAX_BUFFER_SIZE)
                data, address = sock.recvfrom(MAX_BUFFER_SIZE)
                
                #print(f'Recieved recive message {address}: {data}')
                entries = parse_ripv2_packet(data)
                lock.acquire()
                for entry in entries:
                    #if entry.target_ip not in addrs:
                        entry.start_timeout()
                        rip_entries.add(entry)
                    
                lock.release()
            except:
                pass

rip_entries = RIPEntriesList()

def cli():
    while True:
        match input("> "):
            case "entries": 
                string = rip_entries.to_string()
                string.sort()
                for x in string:
                    print(x)
    
def main():
    # Get the list of interfaces
    interfaces = ni.interfaces()
    
    rip_entries.start()
    
    # Create threads to recieve RIPv2 messages on multiple interfaces
    threads = []
    for interface in interfaces:
        if interface not in ['lo']:
            thread = threading.Thread(target=listenRequestPackets, args=[interface], name= "Listen Request packets on " + interface + " thread")
            thread2 = threading.Thread(target=sendRequests, args=[create_rip_message(1, {}), interface], name="Send on " + interface + " thread")
            thread3 = threading.Thread(target=listenRecievePackets, args=[interface], name="Listen Recieve packets on " + interface + " thread")
            threads.append(thread)
            threads.append(thread2)
            threads.append(thread3)
    threads.append(threading.Thread(target=cli))
    for thread in threads:
        thread.start()

    # Wait for the threads to finish
    for thread in threads:
        thread.join()
    
        
    

if __name__ == "__main__":
    main()
