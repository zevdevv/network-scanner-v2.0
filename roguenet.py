# ROGUENET – OOP WI-FI OVERLORD – ZEVDEVV’S WORD-BASED DOMINION

import socket
import threading
from queue import Queue
from colorama import init, Fore, Style
import time
import os
import sys
import scapy.all as scapy  # `pip3 install scapy`
import netifaces  # `pip3 install netifaces`
import csv  # FOR OUI DATABASE

# COLORS – ZEVDEVV’S WARLORD PALETTE
init()
PURPLE = Fore.MAGENTA
BLUE = Fore.BLUE
PINK = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL

# ZEVDEVV’S BADASS WORD-BASED ROGUENET ART – NO BREAKS, PURE POWER
ZEVDEVV_ROGUENET = (
    PURPLE + "  Z Z Z Z Z       E E E E E E       V V V V V       D D D D D       E E E E E E       V V V V V\n" +
    PURPLE + "  Z         Z     E                V       V       D         D     E                V       V\n" +
    BLUE + "   Z           Z    E                V       V       D           D   E                V       V\n" +
    BLUE + "   Z           Z    E                V       V       D           D   E                V       V\n" +
    PINK + "    Z         Z     E E E E E E     V       V       D         D     E E E E E E     V       V\n" +
    PINK + "     Z       Z      E                V       V       D         D     E                V       V\n" +
    BLUE + "      Z   Z        E                V       V       D           D   E                V       V\n" +
    BLUE + "       Z Z         E E E E E E       V V V V V       D D D D D     E E E E E E       V V V V V" + RESET
)

class OUILookup:
    def __init__(self, oui_file="oui.txt"):
        self.oui_db = {}
        self.load_oui(oui_file)

    def load_oui(self, oui_file):
        try:
            # CHECK IF OUI FILE EXISTS, CREATE IF NOT
            if not os.path.exists(oui_file):
                print(f"{YELLOW}[RogueNet] OUI file {oui_file} not found—using 'Unknown Vendor'.{RESET}")
                self.oui_db = {}
                return
            with open(oui_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        parts = line.strip().split("\t")
                        if len(parts) >= 2:
                            oui = parts[0].replace("-", "").upper()
                            vendor = parts[1]
                            self.oui_db[oui] = vendor
        except Exception as e:
            print(f"{YELLOW}[RogueNet] OUI load failed: {e}—using 'Unknown Vendor'.{RESET}")
            self.oui_db = {}

    def get_vendor(self, mac):
        oui = mac[:8].replace(":", "").upper()
        return self.oui_db.get(oui, "Unknown Vendor")

class NetworkScanner:
    def __init__(self, timeout=1, threads=50):
        self.timeout = timeout
        self.threads = threads
        self.scan_queue = Queue()
        self.results = {}
        self.lock = threading.Lock()
        self.total_ips = 0
        self.interface = self.get_default_interface()
        self.base_ip, self.subnet = self.get_network_range()
        self.port_map = {22: "SSH", 80: "HTTP", 443: "HTTPS", 53: "DNS", 21: "FTP", 23: "Telnet", 445: "SMB", 25: "SMTP"}
        self.bytes_sent = {}
        self.bytes_received = {}
        self.oui = OUILookup()
        self.alerts = []
        self.dns_queries = {}

    def get_default_interface(self):
        try:
            gateways = netifaces.gateways()
            return gateways['default'][netifaces.AF_INET][1]
        except Exception as e:
            print(f"{YELLOW}[RogueNet] Default interface error: {e}—using 'en0' (Wi-Fi).{RESET}")
            return "en0"  # DEFAULT WI-FI ON MAC

    def get_network_range(self):
        try:
            gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
            base_ip = ".".join(gateway.split(".")[:-1])
            return base_ip, "255.255.255.0"
        except Exception as e:
            print(f"{YELLOW}[RogueNet] Gateway error: {e}—using 192.168.1.x as default.{RESET}")
            return "192.168.1", "255.255.255.0"

    def arp_scan(self, ip):
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            answered = scapy.srp(packet, timeout=self.timeout, verbose=False, iface=self.interface)[0]
            if answered:
                mac = answered[0][1].hwsrc
                hostname = socket.getfqdn(ip) if socket.getfqdn(ip) != ip else "Unknown"
                vendor = self.oui.get_vendor(mac)
                return {"mac": mac, "hostname": hostname, "vendor": vendor, "ports": {}, "activity": [], "dns": []}
        except Exception as e:
            print(f"{YELLOW}[RogueNet] ARP scan failed for {ip}: {e}{RESET}")
            return None
        return None

    def sniff_traffic(self, ip, duration=5):
        activity = []
        dns_list = []
        def packet_callback(packet):
            try:
                if packet.haslayer(scapy.IP) and (packet[scapy.IP].src == ip or packet[scapy.IP].dst == ip):
                    src, dst = packet[scapy.IP].src, packet[scapy.IP].dst
                    sport = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else "N/A"
                    dport = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else "N/A"
                    size = len(packet)
                    with self.lock:
                        if src == ip:
                            self.bytes_sent[ip] = self.bytes_sent.get(ip, 0) + size
                        if dst == ip:
                            self.bytes_received[ip] = self.bytes_received.get(ip, 0) + size
                    action = self.port_map.get(dport, "Unknown") if dport in self.port_map else self.port_map.get(sport, "Unknown")
                    activity.append(f"{src}:{sport} -> {dst}:{dport} ({action})")
                    self.check_alerts(ip, dport, size)
                    if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:  # DNS QUERY
                        domain = packet[scapy.DNS].qd.qname.decode("utf-8").rstrip(".")
                        if domain not in dns_list:
                            dns_list.append(domain)
            except Exception as e:
                print(f"{YELLOW}[RogueNet] Packet sniff error for {ip}: {e}{RESET}")
        try:
            scapy.sniff(iface=self.interface, prn=packet_callback, timeout=duration, store=0)
        except Exception as e:
            print(f"{YELLOW}[RogueNet] Sniff failed on {self.interface}: {e}—using 'en0' fallback.{RESET}")
            self.interface = "en0"  # FALLBACK WI-FI
            scapy.sniff(iface=self.interface, prn=packet_callback, timeout=duration, store=0)
        return activity[:5], dns_list[:5]

    def check_alerts(self, ip, port, size):
        threshold = 1000
        if size > threshold:
            alert = f"{YELLOW}[ALERT] {ip} spiked {size} bytes on port {port}!{RESET}"
            with self.lock:
                if alert not in self.alerts:
                    self.alerts.append(alert)
                    print(alert)
                    try:
                        os.system("say 'Intruder detected!'")  # MAC ALERT SOUND
                    except Exception as e:
                        print(f"{PINK}[RogueNet] Sound failed: {e}—use speakers!{RESET}")

    def worker(self):
        while not self.scan_queue.empty():
            ip = self.scan_queue.get()
            details = self.arp_scan(ip)
            if details:
                ports_data, dns_data = self.sniff_traffic(ip)
                details["ports"] = self.scan_ports(ip)
                details["activity"] = ports_data
                details["dns"] = dns_data
                with self.lock:
                    self.results[ip] = details
            self.scan_queue.task_done()

    def scan_ports(self, ip):
        open_ports = {}
        for port in range(1, 1025):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout / 10)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner = self.grab_banner(ip, port)
                    open_ports[port] = banner if banner else "Unknown"
                sock.close()
            except Exception as e:
                print(f"{YELLOW}[RogueNet] Port scan failed for {ip}:{port}: {e}{RESET}")
                pass
        return open_ports

    def grab_banner(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            if port == 80:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip()[:50]
            sock.close()
            return banner if banner else None
        except Exception as e:
            print(f"{YELLOW}[RogueNet] Banner grab failed for {ip}:{port}: {e}{RESET}")
            return None

    def generate_ip_range(self):
        return [f"{self.base_ip}.{i}" for i in range(1, 255)]

    def scan(self):
        ip_range = self.generate_ip_range()
        self.total_ips = len(ip_range)
        for ip in ip_range:
            self.scan_queue.put(ip)
        start_time = time.time()
        for _ in range(min(self.threads, self.total_ips)):
            t = threading.Thread(target=self.worker)
            t.start()
        self.live_dashboard()
        self.scan_queue.join()
        return time.time() - start_time

    def live_dashboard(self):
        while not self.scan_queue.empty():
            remaining = self.scan_queue.qsize()
            done = self.total_ips - remaining
            percent = (done / self.total_ips) * 100
            bar = f"{PINK}[{'#' * (done // 10)}{' ' * ((self.total_ips - done) // 10)}]{RESET}"
            sys.stdout.write(f"\r{PURPLE}zevdevv’s Rogue Dash: {bar} {percent:.1f}% – Devices: {len(self.results)}{RESET}")
            sys.stdout.flush()
            time.sleep(0.2)
        sys.stdout.write(f"\r{PURPLE}zevdevv’s Rogue Dash: [{PINK}{'#' * (self.total_ips // 10)}{RESET}] 100.0% – Devices: {len(self.results)}{RESET}\n")

class ReportGenerator:
    def __init__(self, scanner):
        self.scanner = scanner

    def print_report(self, elapsed_time):
        print(f"\n{GREEN}=== ZEVDEVV’S NINJA WI-FI DOMINION ==={RESET}")
        for ip, details in sorted(self.scanner.results.items()):
            ports = "\n".join([f"    {BLUE}Port {p}{RESET}: {info} ({self.scanner.port_map.get(p, 'Unknown')})" for p, info in details["ports"].items()]) or "No open ports"
            activity = "\n".join([f"    {YELLOW}{act}{RESET}" for act in details["activity"]]) or "No activity detected"
            dns = "\n".join([f"    {YELLOW}DNS Query: {d}{RESET}" for d in details["dns"]]) or "No DNS queries"
            sent = self.scanner.bytes_sent.get(ip, 0)
            received = self.scanner.bytes_received.get(ip, 0)
            print(f"{BLUE}{ip}{RESET} – {GREEN}ROGUE{RESET}")
            print(f"  MAC: {details['mac']}")
            print(f"  Hostname: {details['hostname']}")
            print(f"  Vendor: {details['vendor']}")
            print(f"  Ports:\n{ports}")
            print(f"  Activity:\n{activity}")
            print(f"  DNS Queries:\n{dns}")
            print(f"  Bandwidth: Sent {sent} bytes, Received {received} bytes\n")
        print(f"{PURPLE}Rogue reign completed in {elapsed_time:.2f} seconds.{RESET}")

    def log_report(self, elapsed_time):
        log_path = os.path.expanduser("~/Desktop/zevdevv_scan.log")
        try:
            with open(log_path, "a", encoding="utf-8") as log:
                log.write(f"--- zevdevv Rogue Scan at {time.ctime()} ---\n")
                for ip, details in sorted(self.scanner.results.items()):
                    ports = ", ".join([f"{p}: {info}" for p, info in details["ports"].items()]) or "None"
                    activity = "; ".join(details["activity"]) or "None"
                    dns = "; ".join(details["dns"]) or "None"
                    sent = self.scanner.bytes_sent.get(ip, 0)
                    received = self.scanner.bytes_received.get(ip, 0)
                    log.write(f"{ip} – MAC: {details['mac']}, Host: {details['hostname']}, Vendor: {details['vendor']}, Ports: {ports}, Activity: {activity}, DNS: {dns}, Sent: {sent} bytes, Received: {received} bytes\n")
                log.write(f"Completed in {elapsed_time:.2f} seconds\n\n")
        except Exception as e:
            print(f"{YELLOW}[RogueNet] Log failed: {e}—check Desktop permissions.{RESET}")
        print(f"{BLUE}Logged to {log_path}{RESET}")

class RogueNet:
    def __init__(self):
        self.scanner = NetworkScanner()
        self.reporter = ReportGenerator(self.scanner)

    def run(self):
        print(ZEVDEVV_ROGUENET)
        print(f"{PURPLE}Unleashing ninja devils on your Wi-Fi... zevdevv rules!{RESET}\n")
        try:
            elapsed = self.scanner.scan()
            self.reporter.print_report(elapsed)
            self.reporter.log_report(elapsed)
        except Exception as e:
            print(f"{YELLOW}[RogueNet] Scan failed: {e}—check permissions or dependencies.{RESET}")

def main():
    app = RogueNet()
    app.run()

if __name__ == "__main__":
    main()