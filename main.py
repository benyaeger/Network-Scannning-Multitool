from scapy.layers.inet import Ether
from scapy.layers.l2 import ARP
from scapy.sendrecv import sendp
from scapy.all import sniff
import nmap
from socket import *


def lan_scan():
    packets = []
    for mask in range(1, 255):
        dst = '10.0.0.' + str(mask)
        if dst == gethostbyname(gethostname()):
            continue
        p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=dst)
        packets.append(p)
        packets.append(p)
    sendp(packets)
    answer_packets = sniff(timeout=5, filter="arp")  # Capture ARP reply packets with op code 2 (reply)

    online_hosts = set()
    for answer in answer_packets:
        online_hosts.add(answer.psrc)

    print('{} hosts found in the LAN: {}'.format(len(online_hosts), online_hosts))
    should_continue = True if input('Scan for OS Details? (Y/N)') == 'Y' else False

    online_hosts = list(online_hosts)
    if should_continue:
        nm = nmap.PortScanner()
        for host in online_hosts:
            print('Analyzing {}...'.format(host))
            try:
                nm.scan(host, arguments='-O', timeout=15)
            except nmap.nmap.PortScannerTimeout:
                print('OS Detection Timed Out')
                continue
            try:
                os_detection = nm[host]['osmatch'][0]['name']
                os_detection_accuracy = nm[host]['osmatch'][0]['accuracy']
                print('{} runs {} ({}% Accuracy)'.format(host, os_detection, os_detection_accuracy))
            except KeyError:
                print('OS Detection Failed')
                print(nm)
    else:
        pass


if __name__ == '__main__':
    lan_scan()
