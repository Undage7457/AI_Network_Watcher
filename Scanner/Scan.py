from scapy.all import ARP, Ether, srp
import pandas as pd

target_ip = "192.168.1.1/24"

arp = ARP(pdst=target_ip)

ether = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ether / arp

result = srp(packet, timeout=3, verbose=0)[0]

devices = []

for sent, received in result:
    devices.append({
        "ip": received.psrc,
        "mac": received.hwsrc
    })

df = pd.DataFrame(devices)

print("\nConnected Devices:\n")
print(df)