from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t - '
DATA_TAB_2 = '\t\t - '
DATA_TAB_3 = '\t\t\t - '
DATA_TAB_4 = '\t\t\t\t - '

def process_packet(packet):
    if Ether in packet:
        eth = packet[Ether]
        print("\nEthernet Frame:")
        print(f"{TAB_1}Destination: {eth.dst}, Source: {eth.src}, Type: {eth.type}")

        if IP in packet:
            ip = packet[IP]
            print(f"{TAB_1}IPv4 Packet:")
            print(f"{TAB_2}Version: {ip.version}, Header Length: {ip.ihl}, TTL: {ip.ttl}")
            print(f"{TAB_2}Protocol: {ip.proto}, Source: {ip.src}, Destination: {ip.dst}")

            if ip.proto == 1:  # ICMP
                if ICMP in packet:
                    icmp = packet[ICMP]
                    print(f"{TAB_1}ICMP Packet:")
                    print(f"{TAB_2}Type: {icmp.type}, Code: {icmp.code}, Checksum: {icmp.chksum}")
                    print(f"{TAB_2}Data:")
                    print(format_multi_line(DATA_TAB_3, str(icmp.load) if hasattr(icmp, 'load') else 'No data'))

            elif ip.proto == 6:  # TCP
                if TCP in packet:
                    tcp = packet[TCP]
                    print(f"{TAB_1}TCP Segment:")
                    print(f"{TAB_2}Source Port: {tcp.sport}, Destination Port: {tcp.dport}")
                    print(f"{TAB_2}Sequence: {tcp.seq}, Acknowledgment: {tcp.ack}")
                    print(f"{TAB_2}Flags:")
                    print(f"{TAB_3}URG: {tcp.flags & 0x20}, ACK: {tcp.flags & 0x10}, PSH: {tcp.flags & 0x08}, RST: {tcp.flags & 0x04}, SYN: {tcp.flags & 0x02}, FIN: {tcp.flags & 0x01}")
                    print(f"{TAB_2}Data:")
                    print(format_multi_line(DATA_TAB_3, str(tcp.payload) if tcp.payload else 'No data'))

            elif ip.proto == 17:  # UDP
                if UDP in packet:
                    udp = packet[UDP]
                    print(f"{TAB_1}UDP Segment:")
                    print(f"{TAB_2}Source Port: {udp.sport}, Destination Port: {udp.dport}, Length: {udp.len}")

        else:
            print("Data:")
            print(format_multi_line(DATA_TAB_1, str(packet.load) if hasattr(packet, 'load') else "No data"))

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    print("Starting packet sniffer...")
    sniff(prn=process_packet, store=False)


main()
