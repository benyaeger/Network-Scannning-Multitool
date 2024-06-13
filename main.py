from socket import *
import nmap
from scapy.all import sniff
from scapy.layers.inet import Ether, IP, sr, TCP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sendp
from scapy.all import get_if_addr, conf
import networkx as nx
import matplotlib.pyplot as plt
import threading


def intro_print():
    print('*' * 50)
    print("Welcome to Ben's Network Multitool")
    print('*' * 50)


def _scan_subnet(subnet_prefix, startA, endA, startB, endB):
    packets = []
    for maskA in range(startA, endA):
        for maskB in range(startB, endB):
            dst = subnet_prefix + str(maskA) + '.' + str(maskB)
            print(dst)
            if dst == gethostbyname(gethostname()):
                continue
            p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=dst)
            packets.append(p)
    sendp(packets, verbose=0)


def lan_scan():
    print("Scanning Network for Online Hosts...")
    # Automatically get the default network interface
    interface = conf.iface
    local_ip = get_if_addr(interface)
    subnet_prefix = ".".join(local_ip.split('.')[0:2]) + '.'

    print(f"Local IP: {local_ip}")
    print(f"Subnet Prefix: {subnet_prefix}")

    threads = []
    for i in range(1, 255, 64):
        print(f"Starting scan from {subnet_prefix}{i}.1 to {subnet_prefix}{i + 64}.255")
        t = threading.Thread(target=_scan_subnet, args=(subnet_prefix, i, min(i + 64, 255), 1, 255))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    answer_packets = sniff(timeout=5, filter="arp")  # Capture ARP reply packets with op code 2 (reply)
    print(answer_packets)
    online_hosts = set()
    for answer in answer_packets:
        online_hosts.add(answer.psrc)

    print('{} hosts found in the LAN: {}'.format(len(online_hosts), online_hosts))
    should_visualize = input("Preview Network Graph? (Y/N)")
    if should_visualize.upper() == "Y":
        localhost = gethostbyname(gethostname())
        g = nx.Graph()
        online_hosts = list(online_hosts)
        for host in online_hosts:
            g.add_edge(localhost, host)
        options = {
            "font_size": 10,
            "node_size": 4000,
            "node_color": "orange",
            "edgecolors": "black",
            "linewidths": 4,
            "width": 5,
        }
        nx.draw_networkx(g, **options)
        ax = plt.gca()
        ax.margins(0.20)
        plt.axis("off")
        plt.show()
    else:
        pass


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
