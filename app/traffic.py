from app.database import TrafficRecord, engine
from sqlalchemy.orm import sessionmaker
from scapy.all import sniff, IP, IPv6, TCP, UDP
from collections import Counter
from datetime import datetime

packet_count = 0
protocols = Counter()
destinations = Counter()
ports = Counter()
total_bytes = 0
tcp_count = 0
udp_count = 0

def process_packet(packet):
    global packet_count
    global tcp_count, udp_count
    global total_bytes

    total_bytes += len(packet)

    timestamp = datetime.now()

    packet_count += 1

    if packet.haslayer(TCP):
        tcp_count+=1
        protocols["TCP"] += 1
        ports[packet["TCP"].dport] += 1

    elif packet.haslayer(UDP):
        udp_count+=1
        protocols["UDP"] += 1
        ports[packet["UDP"].dport] += 1

    else:
        protocols["Other"] += 1

    if packet.haslayer(IP):
        destinations[packet[IP].dst] += 1

    elif packet.haslayer(IPv6):
        destinations[packet[IPv6].dst] += 1

def main():
    global packet_count, total_bytes, tcp_count, udp_count

    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        for _ in range(100):
            print("\nCollecting traffic for 10 seconds...")

            sniff(
                timeout=10,
                prn=process_packet,
                store=False
            )

            record = TrafficRecord(
                timestamp=datetime.now(),
                packet_count=packet_count,
                total_bytes=total_bytes,
                tcp_count=tcp_count,
                udp_count=udp_count,
                unique_destinations=len(destinations),
                unique_ports=len(ports)
            )

            session.add(record)
            session.commit()

            print("Packets captured:", packet_count)
            print("Total bytes:", total_bytes)
            print("TCP:", tcp_count)
            print("UDP:", udp_count)
            print("Traffic record saved.")

            packet_count = 0
            total_bytes = 0
            tcp_count = 0
            udp_count = 0
            destinations.clear()
            ports.clear()

    except KeyboardInterrupt:
        print("\nCollector stopped.")

    finally:
        session.close()


if __name__ == "__main__":
    main()