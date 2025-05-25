"""
Packet Sniffer using Scapy
===========================

This script captures and displays details of one network packet using the Scapy library.

Supported Layers:
- Ethernet
- ARP
- IP (IPv4)
    - ICMP
    - TCP
    - UDP

✅ REQUIREMENTS:
1. Python 3.x
2. Scapy
3. Npcap (for Windows users)

-------------------------------------------
🧩 STEP 1: Install Npcap (For Windows Users)
-------------------------------------------
Npcap is a packet capture driver required for sniffing network traffic on Windows.

🔗 Download from: https://npcap.com/#download

During installation:
✔️ Check the box: "Install Npcap in WinPcap API-compatible Mode"
✔️ Allow installation in "Normal Mode"
❗ Reboot your system if prompted.

-------------------------------------------
📦 STEP 2: Install Python Dependencies
-------------------------------------------
Open Command Prompt or Terminal and run:

> pip install scapy

-------------------------------------------
🚀 STEP 3: Run the Script
-------------------------------------------
Run the script using Python:

> python packet_sniffer.py

📡 Once running, the script waits for a single packet on any interface and prints detailed information.

"""


from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP
import textwrap

TAB = '\t - '
TAB2 = '\t\t - '

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def process_packet(packet):
    print("\n========== PACKET DETAILS ==========\n")

    if Ether in packet:
        eth = packet[Ether]
        print("[ Ethernet Frame Header ]")
        print(f"{TAB}Destination MAC Address: {eth.dst}")
        print(f"{TAB}Source MAC Address: {eth.src}")
        print(f"{TAB}EtherType: {eth.type} (Indicates next protocol)\n")

        # ARP Packet
        if eth.type == 0x0806 and ARP in packet:
            arp = packet[ARP]
            print("[ ARP Packet ]")
            print(f"{TAB}Hardware Type: {arp.hwtype}")
            print(f"{TAB}Protocol Type: {arp.ptype}")
            print(f"{TAB}Operation: {arp.op} ({'Request' if arp.op == 1 else 'Reply'})")
            print(f"{TAB}Sender MAC Address: {arp.hwsrc}")
            print(f"{TAB}Sender IP Address: {arp.psrc}")
            print(f"{TAB}Target MAC Address: {arp.hwdst}")
            print(f"{TAB}Target IP Address: {arp.pdst}")

        # IP Packet
        elif IP in packet:
            ip = packet[IP]
            print("[ IP Header (IPv4) ]")
            print(f"{TAB}Version: {ip.version}")
            print(f"{TAB}Header Length: {ip.ihl * 4} bytes")
            print(f"{TAB}Time To Live (TTL): {ip.ttl}")
            print(f"{TAB}Protocol: {ip.proto} (1=ICMP, 6=TCP, 17=UDP)")
            print(f"{TAB}Source IP Address: {ip.src}")
            print(f"{TAB}Destination IP Address: {ip.dst}\n")

            if ip.proto == 1 and ICMP in packet:
                icmp = packet[ICMP]
                print("[ ICMP Header ]")
                print(f"{TAB}Type: {icmp.type}")
                print(f"{TAB}Code: {icmp.code}")
                print(f"{TAB}Checksum: {icmp.chksum}")
                print(f"{TAB}Payload:")
                data = str(icmp.load) if hasattr(icmp, 'load') else 'No data'
                print(format_multi_line(TAB2, data))

            elif ip.proto == 6 and TCP in packet:
                tcp = packet[TCP]
                print("[ TCP Header ]")
                print(f"{TAB}Source Port: {tcp.sport}")
                print(f"{TAB}Destination Port: {tcp.dport}")
                print(f"{TAB}Sequence Number: {tcp.seq}")
                print(f"{TAB}Acknowledgment Number: {tcp.ack}")
                print(f"{TAB}Flags:")
                print(f"{TAB2}URG: {bool(tcp.flags & 0x20)}, ACK: {bool(tcp.flags & 0x10)}, PSH: {bool(tcp.flags & 0x08)},")
                print(f"{TAB2}RST: {bool(tcp.flags & 0x04)}, SYN: {bool(tcp.flags & 0x02)}, FIN: {bool(tcp.flags & 0x01)}")
                print(f"{TAB}Payload:")
                print(format_multi_line(TAB2, str(tcp.payload) if tcp.payload else 'No data'))

            elif ip.proto == 17 and UDP in packet:
                udp = packet[UDP]
                print("[ UDP Header ]")
                print(f"{TAB}Source Port: {udp.sport}")
                print(f"{TAB}Destination Port: {udp.dport}")
                print(f"{TAB}Length: {udp.len}")
                print(f"{TAB}Payload:")
                print(format_multi_line(TAB2, str(udp.payload) if udp.payload else 'No data'))

        else:
            print("[ Raw Data Only - No IP Layer ]")
            print(f"{TAB}No data")

    print("\n========== END OF PACKET ==========")

def main():
    print("Sniffing... Please send any network traffic")
    sniff(prn=process_packet, store=False, count=1)

main()
