from scapy.all import sniff, IP, IPv6, TCP, UDP

print("Listening for packets...")

packet = sniff(count=1)[0]

if IP in packet:
    print("Source IP:", packet[IP].src)
    print("Destination IP:", packet[IP].dst)

elif IPv6 in packet:
    print("Source IP:", packet[IPv6].src)
    print("Destination IP:", packet[IPv6].dst)

if TCP in packet:
    print("Protocol: TCP")
    print("Source port:", packet[TCP].sport)
    print("Destination port:", packet[TCP].dport)

elif UDP in packet:
    print("Protocol: UDP")
    print("Source port:", packet[UDP].sport)
    print("Destination port:", packet[UDP].dport)