import struct
import random

def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def inet_aton(ip):
    return bytes(map(int, ip.split('.')))

def create_ethernet_header():
    src_mac = b'\xaa\xbb\xcc\xdd\xee\xff'  # MAC source fictive
    dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast
    eth_type = struct.pack('!H', 0x0800)   # Type IPv4
    return dst_mac + src_mac + eth_type

def create_ip_header(src_ip, dst_ip):
    version_ihl = 0x45  
    tos = 0
    total_length = 40 
    identification = random.randint(0, 65535)
    flags_fragment_offset = 0
    ttl = 64
    protocol = 6  # TCP
    header_checksum = 0
    src_ip_bytes = inet_aton(src_ip)
    dst_ip_bytes = inet_aton(dst_ip)
    
    ip_header = struct.pack('!BBHHHBBH4s4s', 
                            version_ihl, tos, total_length, identification, 
                            flags_fragment_offset, ttl, protocol, header_checksum, 
                            src_ip_bytes, dst_ip_bytes)
    
    header_checksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', 
                            version_ihl, tos, total_length, identification, 
                            flags_fragment_offset, ttl, protocol, header_checksum, 
                            src_ip_bytes, dst_ip_bytes)
    return ip_header

def create_tcp_header(src_port, dst_port):
    seq_number = random.randint(0, 4294967295)
    ack_number = 0
    offset_reserved = (5 << 4) 
    flags = 2  # SYN
    window = 8192
    checksum = 0
    urgent_pointer = 0
    
    tcp_header = struct.pack('!HHLLBBHHH',
                              src_port, dst_port, seq_number, ack_number,
                              offset_reserved, flags, window, checksum,
                              urgent_pointer)
    return tcp_header

def create_packet(src_ip, dst_ip, src_port, dst_port):
    ethernet_header = create_ethernet_header()
    ip_header = create_ip_header(src_ip, dst_ip)
    tcp_header = create_tcp_header(src_port, dst_port)
    return ethernet_header + ip_header + tcp_header

def write_pcap(filename, packet):
    pcap_header = struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    ts_sec, ts_usec = 0, 0
    pkt_len = len(packet)
    pkt_header = struct.pack('!IIII', ts_sec, ts_usec, pkt_len, pkt_len)
    
    with open(filename, 'wb') as f:
        f.write(pcap_header)
        f.write(pkt_header)
        f.write(packet)

def main():
    while True:
        src_ip = input("Entrez l'adresse IP source: ")
        dst_ip = input("Entrez l'adresse IP destination: ")
        src_port = random.randint(1024, 65535)
        dst_port = 80
        
        packet = create_packet(src_ip, dst_ip, src_port, dst_port)
        write_pcap("packet.pcap", packet)
        print("Paquet enregistré dans packet.pcap, lisible par Wireshark.")

        choice = input("Voulez-vous créer un autre paquet? (o/n): ")
        if choice.lower() != 'o':
            break

if __name__ == "__main__":
    main()
