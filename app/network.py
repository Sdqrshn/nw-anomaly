import psutil
import socket
import ipaddress
import subprocess

for interface, addresses in psutil.net_if_addrs().items():
    if interface != "Wi-Fi":
        continue

    for address in addresses:
        if address.family == socket.AF_INET:
            network = ipaddress.ip_network(
                f"{address.address}/{address.netmask}",
                strict=False
            )

            for host in network.hosts():
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "500", str(host)],
                    stdout=subprocess.DEVNULL
                )

                if result.returncode == 0:
                    print("Active:", host)