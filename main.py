from scapy.layers.inet import IP, TCP, UDP, sr1, ICMP, sr, Ether
from scapy.layers.l2 import ARP
from scapy.sendrecv import sendp
from scapy.all import sniff
import psutil


def get_subnet_mask(interface_type):
    try:
        # get all network interfaces on machine
        net_if_addrs = psutil.net_if_addrs()
        # If desired interface type exists
        if interface_type in net_if_addrs:
            for addr in net_if_addrs[interface_type]:
                # addr.family value of 2 is IPv4
                if addr.family == 2:
                    # return subnet mask of interface
                    return addr.netmask
    except Exception as e:
        print(f"Error: {e}")
        return None


def lan_scan():
    packets = []
    for mask in range(1, 255):
        dst = '10.0.0.' + str(mask)
        p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=dst)
        packets.append(p)
    sendp(packets)
    answer_packets = sniff(timeout=5, filter="arp")  # Capture ARP reply packets with op code 2 (reply)
    print(answer_packets)
    for answer in answer_packets:
        print('{} responded and is Online.'.format(answer.psrc))


if __name__ == '__main__':
    lan_scan()
