import tkinter as tk
from socket import *
from tkinter import ttk, scrolledtext, messagebox

import matplotlib.pyplot as plt
import networkx as nx
import nmap
from scapy.all import get_if_addr, conf
from scapy.layers.inet import IP, sr, TCP
from scapy.layers.l2 import arping


class NetworkMultitoolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ben's Network Multitool")
        self.create_widgets()

    def create_widgets(self):
        # Set styles for a more appealing UI
        style = ttk.Style()
        style.configure('TFrame', background='black')
        style.configure('TLabel', background='black', foreground='yellow', font=('Helvetica', 14, 'bold'))
        style.configure('TButton', background='yellow', foreground='black', font=('Helvetica', 12))
        style.configure('TEntry', background='yellow', foreground='black')

        self.frame = ttk.Frame(self.root, padding=10, style='TFrame')
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.frame.columnconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=1)
        self.frame.columnconfigure(2, weight=1)
        self.frame.rowconfigure(4, weight=1)

        ttk.Label(self.frame, text="Network Scanner", style='TLabel').grid(column=0, row=0, columnspan=3, pady=(0, 10))

        self.scan_lan_button = ttk.Button(self.frame, text="LAN Scan", command=self.lan_scan, style='TButton')
        self.scan_lan_button.grid(column=0, row=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        self.os_detect_button = ttk.Button(self.frame, text="OS Detection", command=self.os_detect, style='TButton')
        self.os_detect_button.grid(column=1, row=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        self.port_scan_button = ttk.Button(self.frame, text="Port Scan", command=self.port_scan, style='TButton')
        self.port_scan_button.grid(column=2, row=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        self.clear_button = ttk.Button(self.frame, text="Clear Terminal", command=self.clear_terminal, style='TButton')
        self.clear_button.grid(column=0, row=2, columnspan=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        self.quit_button = ttk.Button(self.frame, text="Quit", command=self.root.destroy, style='TButton')
        self.quit_button.grid(column=1, row=2, columnspan=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        self.output_text = scrolledtext.ScrolledText(self.frame, wrap=tk.WORD, bg='black', fg='yellow')
        self.output_text.grid(column=0, row=4, columnspan=3, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))

    def write_to_terminal(self, message):
        self.output_text.insert(tk.END, message + '\n')
        self.output_text.see(tk.END)

    def clear_terminal(self):
        self.output_text.delete(1.0, tk.END)

    def lan_scan(self):
        self.write_to_terminal("Initiating LAN Scan...")
        self.write_to_terminal("Scanning Network for Online Hosts...")
        interface = conf.iface
        local_ip = get_if_addr(interface)
        subnet = ".".join(local_ip.split('.')[0:3]) + ".0/24"

        self.write_to_terminal(f"Local IP: {local_ip}")
        self.write_to_terminal(f"Subnet: {subnet}")

        arp_answers, _ = arping(subnet, verbose=0)
        online_hosts = set()
        for query_answer in arp_answers:
            packet = query_answer.answer
            found_host = packet["ARP"].psrc
            online_hosts.add(found_host)

        self.write_to_terminal('{} hosts found in the LAN: {}'.format(len(online_hosts), online_hosts))
        should_visualize = messagebox.askyesno("Network Graph", "Preview Network Graph?")
        if should_visualize:
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

    def os_detect(self):
        host = self.prompt_for_input("Enter Target Host: ")
        if host:
            self.write_to_terminal("Initiating OS Detection...")
            self.write_to_terminal(f"Performing OS Scan on {host}...")
            nm = nmap.PortScanner()
            try:
                nm.scan(host, arguments='-O', timeout=15)
                os_detection = nm[host]['osmatch'][0]['name']
                os_detection_accuracy = nm[host]['osmatch'][0]['accuracy']
                self.write_to_terminal('{} runs {} ({}% Accuracy)'.format(host, os_detection, os_detection_accuracy))
            except (nmap.nmap.PortScannerTimeout, KeyError):
                self.write_to_terminal('OS Detection Failed')

    def port_scan(self):
        host = self.prompt_for_input("Enter Target Host: ")
        if host:
            self.write_to_terminal("Initiating Port Scan...")
            self.write_to_terminal(f"Performing Port Scan on {host}...")
            ans, _ = sr(IP(dst=host) / TCP(dport=(0, 1023), flags='S'), verbose=0, timeout=5)
            open_ports = []
            for sent, received in ans:
                if received.haslayer(TCP) and received.haslayer(IP):
                    tcp_layer = received.getlayer(TCP)
                    if tcp_layer.flags == 'SA':
                        open_ports.append(received)
                        try:
                            service = getservbyport(tcp_layer.sport)
                        except OSError:
                            service = 'unknown'
                        self.write_to_terminal("port {} ({}) is open".format(tcp_layer.sport, service))
            if not open_ports:
                self.write_to_terminal("No Open Ports Found on host {}".format(host))

    def prompt_for_input(self, prompt):
        input_window = tk.Toplevel(self.root)
        input_window.title(prompt)
        input_window.grab_set()

        ttk.Label(input_window, text=prompt).grid(column=0, row=0, padx=10, pady=10)
        user_input = tk.StringVar()
        input_entry = ttk.Entry(input_window, textvariable=user_input)
        input_entry.grid(column=1, row=0, padx=10, pady=10)
        input_entry.focus()

        def on_submit():
            input_window.destroy()

        ttk.Button(input_window, text="OK", command=on_submit).grid(column=0, row=1, columnspan=2, pady=10)

        self.root.wait_window(input_window)
        return user_input.get()


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMultitoolApp(root)
    root.mainloop()
