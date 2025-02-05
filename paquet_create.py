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

def create_ip_header(src_ip, dst_ip):
    version_ihl = 0x45  
    tos = 0
    total_length = 40 
    identification = random.randint(0, 65535)
    flags_fragment_offset = 0
    ttl = 64
    protocol = 6 
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
    flags = 2  
    window = 8192
    checksum = 0
    urgent_pointer = 0
    
    tcp_header = struct.pack('!HHLLBBHHH',
                              src_port, dst_port, seq_number, ack_number,
                              offset_reserved, flags, window, checksum,
                              urgent_pointer)
    return tcp_header

def create_packet(src_ip, dst_ip, src_port, dst_port):
    ip_header = create_ip_header(src_ip, dst_ip)
    tcp_header = create_tcp_header(src_port, dst_port)
    return ip_header + tcp_header

if __name__ == "__main__":
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.1"
    src_port = random.randint(1024, 65535)
    dst_port = 80
    packet = create_packet(src_ip, dst_ip, src_port, dst_port)
    
    with open("packet.bin", "wb") as f:
        f.write(packet)
