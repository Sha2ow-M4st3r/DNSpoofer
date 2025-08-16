# DNSpoofer

This is a simple Python script designed to implementing DNS spoofing attacks on the network. It is important to note that the script is not very fast due to the lack of multi-threading. This script is only useful for learning network socket programming in Python with scapy and for modeling and implementing it on a small network.

NOTE1: The script must be run with root access on Linux. 

NOTE2: I think the scapy is not installed by default on your system and you need to install it using APT or PIP. 

NOTE3: The number of values in the ip address list must be the same as the number of values in the domain names list


Identifying DNS queries using packet.haslayer(DNSQR)
Extracting the domain name and stripping the trailing dot
Checking if the domain is in your spoof list
Building a DNS response packet using Scapy's layering syntax and send it

## Usage

```markdown
sudo python3 dnspoof.py --iface <iface> --ipaddr <addresses list> --domain <domain list>
sudo python3 dnspoof.py --iface vboxnet0 --ipaddr ipaddress.txt --domain domains.txt
```
