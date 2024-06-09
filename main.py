from socket import *
import nmap
from scapy.all import sniff
from scapy.layers.inet import Ether, IP, sr, TCP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sendp


def intro_print():
    print('*' * 50)
    print("Welcome to Ben's Network Multitool")
    print('*' * 50)


def lan_scan():
    print("Scanning Network for Online Hosts...")
    packets = []
    for mask in range(1, 255):
        dst = '10.0.0.' + str(mask)
        if dst == gethostbyname(gethostname()):
            continue
        p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=dst)
        packets.append(p)
        packets.append(p)
        packets.append(p)
    sendp(packets, verbose=0)
    answer_packets = sniff(timeout=5, filter="arp")  # Capture ARP reply packets with op code 2 (reply)

    online_hosts = set()
    for answer in answer_packets:
        online_hosts.add(answer.psrc)

    print('{} hosts found in the LAN: {}'.format(len(online_hosts), online_hosts))


def os_detect():
    host = input("Enter Target Host: ")
    print("Performing OS Scan...")
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments='-O', timeout=15)
    except nmap.nmap.PortScannerTimeout:
        print('OS Detection Timed Out')
    try:
        os_detection = nm[host]['osmatch'][0]['name']
        os_detection_accuracy = nm[host]['osmatch'][0]['accuracy']
        print('{} runs {} ({}% Accuracy)'.format(host, os_detection, os_detection_accuracy))
    except KeyError:
        print('OS Detection Failed')


def port_scan():
    host = input("Enter Target Host: ")
    ans, _ = sr(IP(dst=host) / TCP(dport=(0, 1023), flags='S'), verbose=0, timeout=5)
    open_ports = []
    for sent, received in ans:
        if received.haslayer(TCP) and received.haslayer(IP):
            tcp_layer = received.getlayer(TCP)
        else:
            continue
        if tcp_layer.flags == 'SA':
            open_ports.append(received)
            try:
                service = getservbyport(tcp_layer.sport)
            except OSError:
                service = 'unknown'
            print("port {} ({}) is open".format(tcp_layer.sport, service))
    if len(open_ports) == 0: print("No Open Ports was Found on host {}".format(host))


def esc():
    exit()


operations = {
    1: lan_scan,
    2: os_detect,
    3: port_scan,
    4: esc
}


def tool_picker():
    print("What would you like to perform?")
    for key in operations:
        print("({}) {}".format(key, operations[key].__name__))
    picked_operation = input()
    operations[int(picked_operation)]()


if __name__ == '__main__':
    intro_print()
    while True:
        tool_picker()
