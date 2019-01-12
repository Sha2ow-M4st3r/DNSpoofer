# DNSpoofer

![Screenshot](http://s8.picofile.com/file/8348692776/dns_1_202034.png)

DNSpoofer is a python script that allows you to spoofing dns protocol.

## What is Domain Name System

The Domain Name System (DNS) is a hierarchical decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It associates various information with domain names assigned to each of the participating entities. Most prominently, it translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols.[.....](https://en.wikipedia.org/wiki/Domain_Name_System)

## What is Scapy

Scapy is a powerful interactive packet manipulation program. It is able to forge or decode packets of a wide number of protocols, send them on the wire, capture them, match requests and replies, and much more. It can easily handle most classical tasks like scanning, tracerouting, probing, unit tests, attacks or network discovery (it can replace hping, 85% of nmap, arpspoof, arp-sk, arping, tcpdump, tethereal, p0f, etc.). It also performs very well at a lot of other specific tasks that most other tools can’t handle, like sending invalid frames, injecting your own 802.11 frames, combining technics (VLAN hopping+ARP cache poisoning, VOIP decoding on WEP encrypted channel, …), etc.

[More info](https://scapy.net/)

## What is dns spoofing

DNS spoofing, also referred to as DNS cache poisoning, is a form of computer security hacking in which corrupt Domain Name System data is introduced into the DNS resolver's cache, causing the name server to return an incorrect result record, e.g. an IP address. This results in traffic being diverted to the attacker's computer (or any other computer).

![Screenshot](http://s9.picofile.com/file/8348693650/dns_spoofing.png)

[For more info in wikipedia](https://en.wikipedia.org/wiki/DNS_spoofing)


## Screenshots

![Screenshot](http://s9.picofile.com/file/8348693726/S1.png)
![Screenshot](http://s9.picofile.com/file/8348692042/S2.png)


## Installation

```markdown
- sudo git clone https://github.com/Sha2ow-M4st3r/DNSpoofer.git
- cd PSniffer
- sudo pip install -r requirements.txt
```

## Usage

```markdown
sudo python DNSpoofer.py <IFace> <Spoofed-IP>
```

**Never forget: You Can't Run From Your Shadow. But You Can Invite It To Dance**
