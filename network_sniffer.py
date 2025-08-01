from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    print("="*60)

    if IP in packet:
        print(f"[+] Source IP      : {packet[IP].src}")
        print(f"[+] Destination IP : {packet[IP].dst}")

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = "Other"

        print(f"[+] Protocol       : {protocol}")

        if Raw in packet:
            try:
                payload = packet[Raw].load
                print(f"[+] Payload        : {payload[:50]}")
            except:
                print("[+] Payload        : <Unable to decode>")
    else:
        print("[-] Non-IP Packet")
print("[*] Script started successfully. Waiting for packets...")
sniff(prn=packet_callback, store=False,count=10)

