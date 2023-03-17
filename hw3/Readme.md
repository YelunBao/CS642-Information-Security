python3 scanner.py example.pcap

Detect ARP spoofing attempts: for arp protocol, check whether there are multiple MAC addresses corresponding to single IP.

Detect port scans: Create a dictionary, whose keys are target systems' IPs. The value is the list of ports(unique). After looping whole dataset, output the key whose list is longer than 100.

Detect TCP SYN floods: For all tcp protocol with flag "S", create a dictionary, whose keys are dst IP plus time(in second), and values are SYN counter. Then check whether there are values greater than 100.