# Network Packet Sniffer

Welcome to the Network Packet Sniffer project! This project captures and analyzes network packets to demonstrate how data is transmitted over a network.

## What is a Network Packet Sniffer?

A network packet sniffer is a tool that intercepts and logs traffic passing over a digital network. It captures each packet of data that flows through the network and provides detailed information about it.

## Why Use a Packet Sniffer?

1. **Network Troubleshooting**: Helps diagnose network issues by analyzing traffic.
2. **Network Monitoring**: Monitors network usage and detects unauthorized access or unusual activity.
3. **Security Analysis**: Identifies potential security threats and vulnerabilities.
4. **Protocol Debugging**: Helps developers debug protocol implementations.
5. **Data Analysis**: Provides insights into data transmission patterns and performance.

We'll be using two different approaches: 
1. **Scapy for Windows**
2. **Sockets for Linux**

## Why Two Approaches?
Windows and Linux handle packet capturing a bit differently. Windows can use the Scapy library with npcap, while Linux can use raw sockets directly.

 
