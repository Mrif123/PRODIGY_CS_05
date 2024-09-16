from scapy.all import sniff, IP, Raw

def mask_ip(ip):
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
    return ip

def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            ip_src = mask_ip(packet[IP].src)
            ip_dst = mask_ip(packet[IP].dst)
            protocol = packet[IP].proto

            print(f"Source IP: {ip_src}")
            print(f"Destination IP: {ip_dst}")
            print(f"Protocol: {protocol}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload.decode('utf-8', 'ignore')}")
        print("-" * 50)

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing(interface=None):
    print(f"Starting packet capture on interface: {interface if interface else 'default'}")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing('Wi-Fi')
