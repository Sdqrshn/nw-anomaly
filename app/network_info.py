import psutil
import socket

for interface, addresses in psutil.net_if_addrs().items():
    for address in addresses:
        if address.family == socket.AF_INET:
            print(interface, "→", address.address)