from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

packet_count = 0
alerts = 0

suspicious_ips = [
    "192.168.1.100",
    "10.0.0.50",
    "123.45.67.89"
]

print("\n===================================")
print(" SMART INTRUSION DETECTION SYSTEM ")
print("===================================\n")

def detect(packet):

    global packet_count
    global alerts

    if packet.haslayer(IP):

        packet_count += 1

        src = packet[IP].src
        dst = packet[IP].dst

        protocol = "OTHER"

        if packet.haslayer(TCP):
            protocol = "TCP"

        elif packet.haslayer(UDP):
            protocol = "UDP"

        print(f"[{packet_count}] {src} --> {dst} ({protocol})")

        if src in suspicious_ips:

            alerts += 1

            alert_msg = (
                f"\n[ALERT] Suspicious IP Detected\n"
                f"Time: {datetime.now()}\n"
                f"Source IP: {src}\n"
                f"Destination IP: {dst}\n"
                f"Protocol: {protocol}\n"
            )

            print(alert_msg)

            with open("alerts.txt", "a") as file:
                file.write(alert_msg)
                file.write("\n------------------------\n")

try:
    sniff(prn=detect, store=False, count=100)

except KeyboardInterrupt:
    print("\nMonitoring Stopped")

print("\n========== IDS SUMMARY ==========")
print("Total Packets :", packet_count)
print("Total Alerts  :", alerts)
print("=================================")