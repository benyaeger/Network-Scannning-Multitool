from scapy.layers.inet import IP, TCP, UDP, sr1, ICMP, sr
from scapy.layers.l2 import ARP
from scapy.layers.dhcp import DHCP
from socket import *
import ipaddress
import psutil


def get_subnet_mask(interfaceType):
    try:
        # get all network interfaces on machine
        net_if_addrs = psutil.net_if_addrs()
        # If desired interface type exists
        if interfaceType in net_if_addrs:
            for addr in net_if_addrs[interfaceType]:
                # addr.family value of 2 is IPv4
                if addr.family == 2:
                    # return subnet mask of interface
                    return addr.netmask
    except Exception as e:
        print(f"Error: {e}")
        return None


def lan_scan():
    localhost_addr = ipaddress.IPv4Address(gethostbyname(gethostname()))
    network = ipaddress.IPv4Network(f"{localhost_addr}/{get_subnet_mask("Ethernet")}", strict=False)
    broadcast_addr = str(network.broadcast_address)
    broadcast_packet = IP(dst=broadcast_addr) / UDP() / ARP()
    # Needs to form ARP packets
    print(broadcast_packet.show())
    ans, _ = sr(broadcast_packet, timeout=2, verbose=2)
    print(ans.summary())


if __name__ == '__main__':
    lan_scan()
