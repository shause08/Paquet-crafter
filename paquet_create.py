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

def mac_str_to_bytes(mac_str):
    return bytes(int(x, 16) for x in mac_str.split(':'))

def create_ethernet_header(src_mac, eth_type=0x0800):
    dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast
    return dst_mac + src_mac + struct.pack('!H', eth_type)

def create_ip_header(src_ip, dst_ip, protocol, total_length):
    version_ihl = 0x45  
    tos = 0
    identification = random.randint(0, 65535)
    flags_fragment_offset = 0
    ttl = 64
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

def create_udp_header(src_port, dst_port):
    length = 8  # UDP header length (no payload)
    checksum = 0
    return struct.pack('!HHHH', src_port, dst_port, length, checksum)

def create_arp_packet(src_mac, src_ip, dst_ip):
    htype = 1         # Ethernet
    ptype = 0x0800    # IPv4
    hlen = 6
    plen = 4
    oper = 1          # Request
    sha = src_mac
    spa = inet_aton(src_ip)
    tha = b'\x00\x00\x00\x00\x00\x00'
    tpa = inet_aton(dst_ip)

    arp_payload = struct.pack('!HHBBH6s4s6s4s',
                              htype, ptype, hlen, plen, oper,
                              sha, spa, tha, tpa)
    eth_header = create_ethernet_header(src_mac, eth_type=0x0806)
    return eth_header + arp_payload

def create_packet(src_mac, src_ip, dst_ip, src_port, dst_port, protocol):
    if protocol == 6:  # TCP
        transport_header = create_tcp_header(src_port, dst_port)
        total_length = 20 + len(transport_header)
        ip_header = create_ip_header(src_ip, dst_ip, protocol, total_length)
        ethernet_header = create_ethernet_header(src_mac)
        return ethernet_header + ip_header + transport_header

    elif protocol == 17:  # UDP
        transport_header = create_udp_header(src_port, dst_port)
        total_length = 20 + len(transport_header)
        ip_header = create_ip_header(src_ip, dst_ip, protocol, total_length)
        ethernet_header = create_ethernet_header(src_mac)
        return ethernet_header + ip_header + transport_header

    elif protocol == 0x0806:  # ARP
        return create_arp_packet(src_mac, src_ip, dst_ip)

    else:
        raise ValueError("Protocole non pris en charge (TCP=6, UDP=17, ARP=0x0806)")

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
        proto_input = input("Protocole (tcp/udp/arp): ").lower()

        if proto_input == "tcp":
            protocol = 6
        elif proto_input == "udp":
            protocol = 17
        elif proto_input == "arp":
            protocol = 0x0806
        else:
            print("Protocole non supporté. Choisissez tcp, udp ou arp.")
            continue

        src_mac_str = input("Entrez l'adresse MAC source (ex: aa:bb:cc:dd:ee:ff): ")
        src_mac = mac_str_to_bytes(src_mac_str)

        if protocol in (6, 17):
            src_ip = input("Entrez l'adresse IP source: ")
            dst_ip = input("Entrez l'adresse IP destination: ")
            src_port = int(input("Entrez le port source: "))
            dst_port = int(input("Entrez le port destination: "))
        else:
            src_ip = input("Entrez l'adresse IP source (ARP): ")
            dst_ip = input("Entrez l'adresse IP destination (ARP): ")
            src_port = dst_port = 0

        packet = create_packet(src_mac, src_ip, dst_ip, src_port, dst_port, protocol)
        write_pcap("packet.pcap", packet)
        print("Paquet enregistré dans packet.pcap, lisible par Wireshark.")

        choice = input("Voulez-vous créer un autre paquet? (o/n): ")
        if choice.lower() != 'o':
            break

if __name__ == "__main__":
    main()