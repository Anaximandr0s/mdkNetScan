#!/usr/bin/env python3
#Mohamed Doukkani

import os,sys,socket,ipaddress,argparse,logging
import shutil
from scapy.all import *
from scapy.all import TCP, IP, ICMP
from scapy.layers.l2 import ARP, Ether
from ctypes import *
from threading import Thread
from progress.bar import ChargingBar
from colorama import Fore
from termcolor import colored
import time


red     = Fore.RED
reset   = Fore.RESET
cyan    = Fore.CYAN

OPEN_PORT = 80

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


clear = lambda:os.system('cls' if os.name == 'nt' else 'clear')

__version__ = "v1.0"

def center(text):
    terminal_width = shutil.get_terminal_size().columns
    centered_text = text.center(terminal_width)
    return centered_text

def print_figlet(sleep=True):
    clear()
    banner_text = colored("""
███╗   ███╗██████╗ ██╗  ██╗███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗ ████║██╔══██╗██║ ██╔╝████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔████╔██║██║  ██║█████╔╝ ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
██║╚██╔╝██║██║  ██║██╔═██╗ ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚═╝ ██║██████╔╝██║  ██╗██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
    """, "red"
    )
    title = "mdkNetScan a network scanner tool, developed in Python"
    MyAcc = "https://github.com/doukkani17moha"
    Me = "Authors: @Mohameddoukkani"

    for line in banner_text.split('\n'):
        print(center(line))
    print(center(colored(title, "yellow")))
    print(center(colored(MyAcc,"yellow")))
    print(center(colored(Me,"yellow")))


class Scanner:
    def __init__(self,target=None,my_ip=None,protocol=None,timeout=5,interface=None):
        self.target = target
        self.my_ip = my_ip
        self.protocol = protocol
        self.timeout = timeout
        self.interface = interface
        self.error_occurred = False
#Discovering Ports
    def port_scan(self,port=80):
        self.error_occurred = False
        if self.error_occurred:
            return
        available_interfaces = get_if_list()
        if self.interface is not None and self.interface not in available_interfaces:
            self.error_occurred = True
            return
        pkt = IP(dst=self.target)/TCP(dport=port,flags="S")
        scan = sr1(pkt,timeout=self.timeout if self.timeout else 5,verbose=0, iface=self.interface if self.interface else None)
        if scan == None:
            return {port: 'Filtered'}
        elif scan.haslayer(TCP):
            if scan.getlayer(TCP).flags == 0x12: # 0x12 SYN+ACk
                return {port: 'Open'}
            elif scan.getlayer(TCP).flags == 0x14:
                return {port: 'Closed'}
        elif scan.haslayer(ICMP):
            if int(scan.getlayer(ICMP).type) == 3 and int(scan.getlayer(ICMP).code in [1,2,3,9,10,13]):
                return {port: 'Filtered'}


    def handle_port_response(self,ports_saved,response,port):
        open_ports = ports_saved['open']
        filtered_ports = ports_saved['filtered']
        open_or_filtered = ports_saved['open/filtered']

        if response[port] == "Open":
            open_ports.append(port)
        elif response[port] == "Filtered":
            filtered_ports.append(port)
        elif response[port] == "Open/Filtered":
            open_or_filtered.append(port)
        else:
            pass

        return (
            open_ports,
            filtered_ports,
            open_or_filtered
        )

    def common_scan(self):
        ports = [21,22,23,25,53,67,68,80,161,443,3389]
        open_ports = []
        filtered_ports = []
        open_or_filtered = []
        logging.info("Starting - Stealth TCP Port Scan\n")
        bar = ChargingBar("Scanning...",  max=len(ports))
        start_time = time.time()

        for port in ports:
            if not self.error_occurred :
                scan = self.port_scan(port=port)
                if scan:
                    ports_saved = {
                        "open": open_ports,
                        "filtered": filtered_ports,
                        "open/filtered": open_or_filtered
                    }
                    open_ports, filtered_ports, open_or_filtered = self.handle_port_response(ports_saved=ports_saved,response=scan,port=port)
                bar.next()
        bar.finish()
        if self.error_occurred :
                logging.warning(f"Interface {self.interface} not found. Please check the interface name.")
        if open_ports or filtered_ports or open_or_filtered:
            total = len(open_ports) 
            total2= len(filtered_ports) + len(open_or_filtered)
            print("")
            logging.info(f"Founded {total} Open ports!")
            for port in open_ports:
                service_name = self.get_service_name(port)
                logging.info(f"Port {port}: {service_name} - Open")
            print("************************")
            logging.info(f"Founded {total2} Filtered ports!")
            for port in filtered_ports:
                service_name = self.get_service_name(port)
                logging.info(f"Port {port}: {service_name} - Filtered")

            for port in open_or_filtered:
                logging.info(f"Port: {port} - Open/Filtered")
                service_name = self.get_service_name(port)
                logging.info(f"Service: {service_name}")
        end_time = time.time()
        elapsed_time = round(end_time - start_time, 3)
        logging.info(f'Time taken for TCP port scan: {elapsed_time} seconds')


    def range_scan(self,start,end=None):
        open_ports = []
        filtered_ports = []
        open_or_filtered = []
        logging.info("Starting - TCP Stealth Port Scan\n")
        if end:
            bar = ChargingBar("Scanning...",  max=end-start)
            threads_tcp = [None] * (end-start)
            results_tcp = [None] * (end-start)
            start_time = time.time()
            lock = Lock()
            def scan_thread(port_idx):
                port = start + port_idx 
                if not self.error_occurred:
                    scan = self.port_scan(port=port)
                    results_tcp[port_idx] = scan  
                    with lock:
                        bar.next()  
            # Start the threads
            for i in range(len(threads_tcp)):
                if not self.error_occurred:
                    threads_tcp[i] = Thread(target=scan_thread, args=(i,))
                    threads_tcp[i].start()

            # Join the threads
            for i in range(len(threads_tcp)):
                if not self.error_occurred:
                    threads_tcp[i].join()
            for port_idx, Scanned_port in enumerate(results_tcp):
                port = start + port_idx                    
                if Scanned_port:
                    ports_saved = {
                        "open": open_ports,
                        "filtered": filtered_ports,
                        "open/filtered": open_or_filtered
                    }
                    open_ports, filtered_ports, open_or_filtered = self.handle_port_response(ports_saved=ports_saved,response=Scanned_port,port=port)
            bar.finish()  
            if self.error_occurred :
                logging.warning(f"Interface {self.interface} not found. Please check the interface name.")          
            if open_ports or filtered_ports or open_or_filtered:
                total = len(open_ports) 
                total2= len(filtered_ports) + len(open_or_filtered)
                print("")
                logging.info(f"Founded {total} Open ports!")
                for port in open_ports:
                    service_name = self.get_service_name(port)
                    logging.info(f"Port {port}: {service_name} - Open")
                print("************************")
                logging.info(f"Founded {total2} Filtered ports!")
                for port in filtered_ports:
                    service_name = self.get_service_name(port)
                    logging.info(f"Port {port}: {service_name} - Filtered")
                for port in open_or_filtered:
                    logging.info(f"Port: {port} - Open/Filtered")
                    service_name = self.get_service_name(port)
                    logging.info(f"Service: {service_name}")
            end_time = time.time()
            elapsed_time = round(end_time - start_time, 3)
            logging.info(f'Time taken for TCP port scan: {elapsed_time} seconds')
        else:
            bar = ChargingBar("Scanning...",  max=1)
            start_time = time.time()
            scan = self.port_scan(start)
            bar.next()
            bar.finish()
            if self.error_occurred :
                logging.warning(f"Interface {self.interface} not found. Please check the interface name.")
            if scan:
                service_name = self.get_service_name(start)
                status = list(scan.values())[0] 
                if status == "Open" :
                    logging.info(f"Port {start}: {service_name} - Open")
                elif status == "Filtered" :
                    logging.info(f"Port {start}: {service_name} - Filtered")
                else:
                    logging.debug(f"Port {start}: {service_name} - Unknown status")
            else:
                logging.debug(f"Port {start} - No response")
            end_time = time.time()
            elapsed_time = round(end_time - start_time, 3)
            logging.info(f'Time taken for TCP port scan: {elapsed_time} seconds')


    def get_service_name(self,port):
        try:
            service_name = socket.getservbyport(port)
            return service_name
        except (socket.error, socket.herror, socket.gaierror, socket.timeout):
            return "Unknown Service"


#Discovering OS   
    def scan(self, target, interface=None):
        self.error_occurred = False

        if self.error_occurred:
            return
        available_interfaces = get_if_list()
        if self.interface is not None and self.interface not in available_interfaces:
            self.error_occurred = True
            return
        
        os_ttl = {'Linux/Unix 2.2-2.4 >': 255, 'Linux/Unix 2.0.x kernel (Android)': 64, 'Windows 98': 32, 'Windows': 128}
        pkg = IP(dst=target, ttl=128) / ICMP()
        try:
            if interface:
                ans, uns = sr(pkg, retry=1, timeout=self.timeout if self.timeout else 3, inter=1, verbose=0,
                                iface=self.interface if self.interface else None)
            else:
                ans, uns = sr(pkg, retry=1, timeout=self.timeout if self.timeout else 3, inter=1, verbose=0)
            try:
                target_ttl = ans[0][1].ttl
            except IndexError:
                print("[-] Host did not respond")
                return False 
            for ttl in os_ttl:
                if target_ttl == os_ttl[ttl]:
                    return ttl
        except OSError as e:
            print(f"[-] Error: {e}")
            return False
        except Exception as e:
            print(f"[-] An unexpected error occurred: {e}")
            return False 
    
    def os_scan(self):
        logging.info("Starting - Scanning OS in Hosts with ICMP Protocol")
        bar = ChargingBar("Scanning...", max=1)
        start_time = time.time()
        target_os = self.scan(self.target)
        bar.next()
        bar.finish()
        if not self.error_occurred :
            if target_os:
                print("")
                logging.info(f"Target OS: {target_os}")
            else:
                logging.warning("[[red]-[/red]]Error when scanning OS")
        else:
            logging.warning(f"Interface {self.interface} not found. Please check the interface name.")
        end_time = time.time()
        elapsed_time = round(end_time - start_time, 3)
        logging.info(f'Time taken for OS detection: {elapsed_time} seconds')


# Discovering Network
    def send_icmp(self,target, result, index):
        # print(f"[+]Sending ICMP request to {target}")
        self.error_occurred = False
        if self.error_occurred:
            return

        available_interfaces = get_if_list()
        if self.interface is not None and self.interface not in available_interfaces:
            self.error_occurred = True
            return
        target = str(target)
        host_found = []
        pkg = IP(dst=target)/ICMP()
        answers, unanswered = sr(pkg,timeout=self.timeout if self.timeout else 3, retry=2,verbose=0,iface=self.interface if self.interface else None)
        answers.summary(lambda r : host_found.append(target))

        if host_found: result[index] = host_found[0]
    
    def send_arp(self, target, result2, index2):
        self.error_occurred = False
        if self.error_occurred:
            return

        available_interfaces = get_if_list()
        if self.interface is not None and self.interface not in available_interfaces:
            self.error_occurred = True
            return
        target = str(target)
        host_found = []
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        answers, unanswered = srp(request, timeout=self.timeout if self.timeout else 2, retry=1, verbose=0, iface=self.interface if self.interface else None)
        
        for sent2, received2 in answers:
            host_found.append({'IP': received2.psrc, 'MAC': received2.hwsrc})
        
        if host_found:
            result2[index2] = host_found[0]

    def discover_net(self,ip_range=24):
        protocol = self.protocol
        base_ip = self.my_ip

        base_ip = base_ip.split('.')
        base_ip = f"{str(base_ip[0])}.{str(base_ip[1])}.{str(base_ip[2])}.0/{str(ip_range)}"

        hosts = list(ipaddress.ip_network(base_ip))

        if protocol == "ICMP":
            logging.info("Starting - Discover Hosts Scan with ICMP Protocol")

            bar = ChargingBar("Scanning...", max=len(hosts))
            sys.stdout = None
            bar.start()
            threads_icmp = [None] * len(hosts)
            results_icmp = [None] * len(hosts)
            start_time = time.time()
            for i in range(len(threads_icmp)):
                if not self.error_occurred :
                    threads_icmp[i] = Thread(target=self.send_icmp,args=(hosts[i], results_icmp, i))
                    threads_icmp[i].start()
            for i in range(len(threads_icmp)):
                if not self.error_occurred :
                    threads_icmp[i].join()
                    bar.next()

            bar.finish()
            sys.stdout = sys.__stdout__
            hosts_found_icmp = [i for i in results_icmp if i is not None]
            if self.error_occurred :
                logging.warning(f"Interface {self.interface} not found. Please check the interface name.")
            if not hosts_found_icmp:
                logging.warning('Not found any host')
            else:
                print("")
                logging.info(f'{len(hosts_found_icmp)} ICMP hosts')
                for host_icmp in hosts_found_icmp:
                    logging.info(f'Host found: {host_icmp}')
            end_time = time.time()
            elapsed_time = round(end_time - start_time, 3)
            logging.info(f'Time taken for ICMP scan: {elapsed_time} seconds')
            return True
        else :
            logging.info("Starting - Discover Hosts Scan with ARP Protocol")
            bar = ChargingBar("Scanning...", max=len(hosts))
            sys.stdout = None
            bar.start()
            threads_arp = [None] * len(hosts)
            results_arp = [None] * len(hosts)
            start_time = time.time()
            for j in range(len(threads_arp)):
                if not self.error_occurred :
                    threads_arp[j] = Thread(target=self.send_arp,args=(hosts[j], results_arp, j))
                    threads_arp[j].start()

            for j in range(len(threads_arp)):
                if not self.error_occurred :
                    threads_arp[j].join()
                    bar.next()
            bar.finish()
            sys.stdout = sys.__stdout__
            hosts_found_arp = [j for j in results_arp if j is not None]

            if self.error_occurred :
                logging.warning(f"Interface {self.interface} not found. Please check the interface name.")

            if not hosts_found_arp:
                logging.warning('Not found any host')
            else:
                print("")
                logging.info(f'{len(hosts_found_arp)} ARP hosts found')
                for host_arp in hosts_found_arp:
                    logging.info(f'Host found: {host_arp}')
            end_time = time.time()
            elapsed_time = round(end_time - start_time, 3)
            logging.info(f'Time taken for ARP scan: {elapsed_time} seconds')
            return True

        
def arguments():
    parser = argparse.ArgumentParser(description="mdkNetScan - Network Tool",usage="\n\tTo scan all ports: mdkNetScan.py -sA -H 192.168.1.105\n\tTo scan specified ports: mdkNetScan.py -sP 1-100 -H 192.168.1.105\n\tTo scan os: mdkNetScan.py -sO -H 192.168.1.105\n\tTo discover network: mdkNetScan.py -d -p [ICMP,ARP]")
    
    parser.add_argument('-H',"--Host",help = "Ip address (127.0.0.1)", nargs='?',default=None)
    parser.add_argument('-sC',"--scan-common",help="Scan common ports",action="count")
    parser.add_argument('-sA',"--scan-all",help="Scan all ports",action="count", dest="scan_all")
    parser.add_argument('-sO',"--scan-os",help="Scan OS",action="count")
    parser.add_argument('-sP',"--scan-port",help="Scan defined port 80, [1-443]", nargs='?', action="store", dest="scan_ports")
    parser.add_argument('-d',"--discover",help="Discover hosts in the network",action="count")
    parser.add_argument('-p',"--protocol",help="Protocol to use to discover hosts in the network. ICMP,ARP.",type=str,choices=['ICMP','ARP'],default=None)
    parser.add_argument('-i',"--interface",help="Interface to use",default=None)
    parser.add_argument('-t',"--timeout",help="Timeout to each request",default=5,type=int)

    args = parser.parse_args()

    if not args.discover and not args.Host:
        sys.exit(parser.print_help())

    if not args.scan_common and not args.scan_all and not args.scan_os and not args.scan_ports and not args.discover:
        sys.exit(parser.print_help())

    return (args, parser)

if __name__ == '__main__':
    args, parser = arguments() 

    del logging.root.handlers[:]
  
    logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
    logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
    logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
    logging.addLevelName(logging.DEBUG, f"[{cyan}**{reset}]")
    logging.basicConfig(format="%(levelname)s%(message)s", level=logging.INFO)

    print_figlet()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8",80))
    ip = s.getsockname()[0]
    s.close()

    scanner = Scanner(target=args.Host,my_ip=ip,protocol=args.protocol,timeout=args.timeout,interface=args.interface )

    if args.scan_common:
        scanner.common_scan()

    elif args.scan_all:
        scanner.range_scan(start=0,end=65535)

    if args.scan_ports:
        try:
            if "-" in args.scan_ports:
                start, end = map(int, args.scan_ports.split('-'))
                scanner.range_scan(start=start, end=end)
            else:
                scanner.range_scan(start=int(args.scan_ports))
        except ValueError:
            print("Invalid port or range format.")

    elif args.discover:
        scanner.discover_net() 

    elif args.scan_os:
        scanner.os_scan()

    else:
        parser.print_help()