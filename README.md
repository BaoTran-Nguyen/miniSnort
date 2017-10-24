# miniSnort

"To use this program, use the following commands below:"
							-c <number of packets desired> <name of the rule document>: program will exit after receiving count packets"
							-r <filename.dat> <number of packets desired> <type of packets> <name of the rule document>: the program will read packets from filename"
							-o <filename.dat> <number of packets desired><type of packets> <name of the rule document>: the program will save <number> of outputs to <filename.dat>"
							-t <number of packets desired> <type> <name of the rule document>: the program will print only packets of the "
								 "specified type where type is one of: eth, arp,ip, icmp, tcp or udp"
							-h <number of packets desired> <type> <name of the rule document>: the program will print header info of the "
								+ "specified type where type is one of: eth, arp,ip, icmp, tcp or udp"
							-src <number of packets desired> <saddress> <name of the rule document>: the program will print only packets with source "
								 "address equal to saddress"
							-dst <number of packets desired> <daddress> <name of the rule document>: the program will print only packets with destination " "address equal to daddress"
							-sord <number of packets desired> <saddress daddress> <name of the rule document>: the program will print only packets where 							 "the source address matches saddress or the destination address matches daddress"
							-sandd <number of packets desired> <saddress daddress> <name of the rule document>: the program will print only packets where the source "
							 "address matches saddress and the destination address matches daddress"
							-sport <number of packets desired> <port1 port2> <name of the rule document>: the program will print only packets where the source port " "is in the range port1-port2"
							-dport <number of packets desired> <port1 port2> <name of the rule document>: the program will print only packets where the destination port" "is in the range port1-port2
