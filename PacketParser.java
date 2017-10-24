import java.io.*;
import java.util.ArrayList;

public class PacketParser {
	
	public static void main(String[] args) throws IOException {
		int index = 0;
		while (index < args.length) {
			switch (args[index]) {
				case "-help":
					System.out.print("To use this program, use the following commands below:"
							+ "\n-c <number of packets desired> <name of the rule document>: program will exit after receiving count packets"
							+ "\n-r <filename.dat> <number of packets desired> <type of packets> <name of the rule document>: the program will read packets from filename"
							+ "\n-o <filename.dat> <number of packets desired><type of packets> <name of the rule document>: the program will save <number> of outputs to <filename.dat>"
							+ "\n-t <number of packets desired> <type> <name of the rule document>: the program will print only packets of the "
								+ "specified type where type is one of: eth, arp,ip, icmp, tcp or udp"
							+ "\n-h <number of packets desired> <type> <name of the rule document>: the program will print header info of the "
								+ "specified type where type is one of: eth, arp,ip, icmp, tcp or udp"
							+ "\n-src <number of packets desired> <saddress> <name of the rule document>: the program will print only packets with source "
								+ "address equal to saddress"
							+ "\n-dst <number of packets desired> <daddress> <name of the rule document>: the program will print only packets with destination "
								+ "address equal to daddress"
							+ "\n-sord <number of packets desired> <saddress daddress> <name of the rule document>: the program will print only packets where "
								+ "the source address matches saddress or the destination address matches daddress"
							+ "\n-sandd <number of packets desired> <saddress daddress> <name of the rule document>: the program will print only packets where the source "
								+ "address matches saddress and the destination address matches daddress"
							+ "\n-sport <number of packets desired> <port1 port2> <name of the rule document>: the program will print only packets where the source port "
								+ "is in the range port1-port2"
							+ "\n-dport <number of packets desired> <port1 port2> <name of the rule document>: the program will print only packets where the destination port "
								+ "is in the range port1-port2");
					break;
					
				case "-c": 
					String counts = args[index+1];
					String crule = args[index+2];
					int count = Integer.parseInt(counts); //converting string to int
					byte[] Packet;
					for(int i = 0; i<count; i++){ //receiving count packets
						Packet = EtherParser.etherParser(EtherParser.packetCatcher());
						if (Packet != null){
							if(!packetEvaluator.PacketEvaluator(Packet, crule))	
								System.out.println("Bad Packet");
							System.out.println(Lib.getString(Packet));
						}
					}
					System.out.print(count+" packets have been received ");
					break;
					
				case "-r": //read packet from filename 
					String filenameRead = args[index+1];
					String readType = args[index+2];
					String rule = args[index+3];
					byte[] readEtherPacket = null;
					byte[] readarpPacket = null;
					byte[] readipPacket = null;
					byte[] ricmpPacket = null;
					byte[] rudpPacket = null;
					byte[] rtcpPacket = null;
					ArrayList<byte[]>b = new ArrayList<>();
					b = Lib.read(filenameRead);
					
					for (int j = 0; j < b.size(); j++){
						if (b.get(j).length <= 0){
							break;
						}
						if(readType.equals("eth")){
							readEtherPacket = EtherParser.etherParser(b.get(j));
							if (readEtherPacket !=null){
								if(!packetEvaluator.PacketEvaluator(readEtherPacket, rule))
									System.out.println("Bad packet");			
								System.out.println(EtherParser.getEtherPacket(readEtherPacket)+"\n");
							}
						}
						
						if(readType.equals("arp") && EtherParser.getType(b.get(j)) == 2054){
							readEtherPacket = EtherParser.etherParser(b.get(j));							
							if (readEtherPacket !=null){
								if(!packetEvaluator.PacketEvaluator(readEtherPacket, rule))									
									System.out.println("Bad packet");			
								readarpPacket = arpParser.ARPparser(readEtherPacket);
								System.out.println(arpParser.getARPPacket(readarpPacket));
							}
						}
						
						if(readType.equals("ip") && EtherParser.getType(b.get(j)) == 2048) {
							readEtherPacket = EtherParser.etherParser(b.get(j));							
							if (readEtherPacket !=null){
								if(!packetEvaluator.PacketEvaluator(readEtherPacket, rule))
									System.out.println("Bad packet");			
								readipPacket = ipParser.IPparser(readEtherPacket);
								System.out.println(ipParser.getIPPacket(readipPacket));									
							}
						}
						
						if(readType.equals("icmp") && ipParser.getprot(Lib.copyByteArray(b.get(j),14)).equals("This is a ICMP packet")){//getprot
							readEtherPacket = EtherParser.etherParser(b.get(j));
							if (readEtherPacket !=null){
								if(!packetEvaluator.PacketEvaluator(readEtherPacket, rule))
									System.out.println("Bad packet");
								readipPacket = ipParser.IPparser(readEtherPacket);
								ricmpPacket = icmpParser.ICMPparser(readipPacket);
								System.out.println(icmpParser.getICMPPacket(ricmpPacket));	
																
							}							
						}
						
						if(readType.equals("tcp") && ipParser.getprot(Lib.copyByteArray(b.get(j),14)).equals("This is a TCP packet")){
							readEtherPacket = EtherParser.etherParser(b.get(j));
							if (readEtherPacket !=null){
								if(!packetEvaluator.PacketEvaluator(readEtherPacket, rule))
									System.out.println("Bad packet");
								readipPacket = ipParser.IPparser(readEtherPacket);
								rtcpPacket = tcpParser.TCPparser(readipPacket);
								System.out.println(tcpParser.getTCPPacket(rtcpPacket));		
														
							}												
						}
						
						if(readType.equals("udp") && ipParser.getprot(Lib.copyByteArray(b.get(j),14)).equals("This is a UDP packet")){
							readEtherPacket = EtherParser.etherParser(b.get(j));
							if (readEtherPacket !=null){
								if(!packetEvaluator.PacketEvaluator(readEtherPacket, rule))
									System.out.println("Bad packet");
								readipPacket = ipParser.IPparser(readEtherPacket);
								rudpPacket = udpParser.UDPparser(readipPacket);
								System.out.println(udpParser.getUDPPacket(rudpPacket));		
																	
							}				
						}
					}
					break;
					
				case "-o": //write packets into filename
					OutputStream writeCMD = null;
					DataOutputStream writeIn = null;	
					String filenameWrite = args[index+1];
					String num1 = args[index+2];
					String writeType = args[index+3];
					int writeNum = Integer.parseInt(num1); 
					byte[] writePacket;
					try{
						writeCMD = new FileOutputStream(filenameWrite);
						writeIn = new DataOutputStream(writeCMD);
						for(int j = 0; j < writeNum; j++){
							writePacket = EtherParser.packetCatcher();
							String Packet3 = Lib.getString(writePacket);
							if(writeType.equals("eth")){//if eth, look for byte xxxx
								writeIn.writeUTF((Packet3));
							}
							if(writeType.equals("arp") && Packet3.substring(36, 41).equals("08 06")){
								writeIn.writeUTF(Packet3.substring(42));
							}
							if(writeType.equals("ip") && Packet3.substring(36, 41).equals("08 00")){
								writeIn.writeUTF(Packet3.substring(42));
							}
							if(writeType.equals("icmp") && Packet3.substring(70, 72).equals("01")){
								writeIn.writeUTF(Packet3.substring(70));
							}
							if(writeType.equals("tcp") && Packet3.substring(70, 72).equals("06")){
								writeIn.writeUTF(Packet3.substring(70));
							}
							if(writeType.equals("udp") && Packet3.substring(70, 72).equals("11")){
								writeIn.writeUTF(Packet3.substring(70));
							}
						}
					}catch(Exception e){
						e.printStackTrace();
					}finally{
						if(writeCMD!=null)
							writeCMD.close();
						if(writeIn!=null)
							writeIn.close();
					}
					break;
					
				case "-t": 	//Print only packets of the specified type
					String num2 = args[index+1];
					int typeNum = Integer.parseInt(num2); 
					String type = args[index+2];
					String trule = args[index+3];
					byte[] etherPacket;
					String toPrint = null;
					byte[] arpPacket;
					byte[] ipPacket;
					byte[] icmpPacket;
					byte[] tcpPacket;
					byte[] udpPacket;
					for(int j = 0; j < typeNum; j++){						
						if (type.equals("eth")){ //if eth, prints everything							
							etherPacket = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket, trule))
									System.out.println("Bad Packet");
								toPrint = EtherParser.getEtherPacket(etherPacket);
								System.out.println(toPrint);
								
							}
							continue;
						}
						
						if (type.equals("arp")){ 
							etherPacket = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket, trule))
									System.out.println("Bad Packet");
								arpPacket = arpParser.ARPparser(etherPacket);
								toPrint = arpParser.getARPPacket(arpPacket);
								System.out.println(toPrint);									
								
							}
							continue;
						}
						
						if (type.equals("ip")){
							etherPacket = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket, trule))
									System.out.println("Bad Packet");
								ipPacket = ipParser.IPparser(etherPacket);
								toPrint = ipParser.getIPPacket(ipPacket);
								System.out.println(toPrint);
								
							}							
							continue;
						}
						
						if (type.equals("icmp")){
							etherPacket = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket, trule))
									System.out.println("Bad Packet");
								ipPacket = ipParser.IPparser(etherPacket);
								icmpPacket = icmpParser.ICMPparser(ipPacket);
								toPrint = icmpParser.getICMPPacket(icmpPacket);
								System.out.println(toPrint);
								
							}							
							continue;
						}
						
						if (type.equals("tcp")){
							etherPacket = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket, trule))
									System.out.println("Bad Packet");
								ipPacket = ipParser.IPparser(etherPacket);
								tcpPacket = tcpParser.TCPparser(ipPacket);
								toPrint = tcpParser.getTCPPacket(tcpPacket);
								System.out.println(toPrint);
								
							}							
							continue;
						}
						
						if (type.equals("udp")){
							etherPacket = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket, trule))
									System.out.println("Bad Packet");
								ipPacket = ipParser.IPparser(etherPacket);
								udpPacket = udpParser.UDPparser(ipPacket);
								toPrint = udpParser.getUDPPacket(udpPacket);
								System.out.println(toPrint);
								
							}							
							continue;
						}
					}
					break;
				
				case "-h": //Print header info specified by -t
					String num3 = args[index+1];
					int headerTypeNum = Integer.parseInt(num3); 
					String headerType = args[index+2];
					String hrule = args[index+3];
					String toPrint2;
					byte[] etherPacket2 = null;
					byte[] arpPacket2;
					byte[] ipPacket2;
					byte[] icmpPacket2;
					byte[] tcpPacket2;
					byte[] udpPacket2;
					for (int m = 0; m < headerTypeNum; m++){
						
						if (headerType.equals("eth")){//0,13
							etherPacket2 = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket2 != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket2, hrule))
									System.out.println("Bad Packet");
								toPrint2 = EtherParser.getEtherHeader(etherPacket2);
								System.out.println(toPrint2);
								
							}							
							continue;
						}
						
						if (headerType.equals("arp")){//0,23
							etherPacket2 = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket2 != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket2, hrule))
									System.out.println("Bad Packet");
								arpPacket2 = arpParser.ARPparser(etherPacket2);
								toPrint2 = arpParser.getARPHeader(arpPacket2);
								System.out.println(toPrint2);
								
							}							
							continue;
						}
						
						if (headerType.equals("ip")){//0,23
							etherPacket2 = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket2 != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket2, hrule))
									System.out.println("Bad Packet");
								ipPacket2 = ipParser.IPparser(etherPacket2);
								toPrint2 = ipParser.getIPHeader(ipPacket2);
								System.out.println(toPrint2);
								
							}							
							continue;
						}
						
						if (headerType.equals("icmp")){
							etherPacket2 = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket2 != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket2, hrule))
									System.out.println("Bad Packet");
								ipPacket2 = ipParser.IPparser(etherPacket2);
								icmpPacket2 = icmpParser.ICMPparser(ipPacket2);
								toPrint2 = icmpParser.getICMPHeader(icmpPacket2);
								System.out.println(toPrint2);
								
							}							
							continue;
						}
						
						if (headerType.equals("udp")){
							etherPacket2 = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket2 != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket2, hrule))
									System.out.println("Bad Packet");
								ipPacket2 = ipParser.IPparser(etherPacket2);
								udpPacket2 = udpParser.UDPparser(ipPacket2);
								toPrint2 = udpParser.getUDPHeader(udpPacket2);
								System.out.println(toPrint2);
								
							}							
							continue;
						}
						
						if (headerType.equals("tcp")){
							etherPacket2 = EtherParser.etherParser(EtherParser.packetCatcher());
							if (etherPacket2 != null){
								if(!packetEvaluator.PacketEvaluator(etherPacket2, hrule))
									System.out.println("Bad Packet");
								ipPacket2 = ipParser.IPparser(etherPacket2);
								tcpPacket2 = tcpParser.TCPparser(ipPacket2);
								toPrint2 = tcpParser.getTCPHeader(tcpPacket2);
								System.out.println(toPrint2);
								
							}							
							continue;
						}
					}
					break;
				case "-src": //Print only packets with source address equal to saddress
					String num4 = args[index+1];
					int srcNum = Integer.parseInt(num4); 
					String srcType = args[index+2];
					String saddress = args[index+3];
					String srule = args[index+4];
					saddress = saddress +".";
					
					for (int n = 0; n < srcNum; n++){
						byte[] srcPacket = EtherParser.etherParser(EtherParser.packetCatcher());
						if (srcPacket != null){
							if(packetEvaluator.PacketEvaluator(srcPacket, srule)){
								byte[] ipPacket6 = ipParser.IPparser(srcPacket);
								byte[] arpPacket6 = arpParser.ARPparser(srcPacket);		
								int srcType2 = EtherParser.getType(srcPacket);
								String arpsIPAddr = arpParser.getsIPAddr(arpPacket6);
								String ipIPS = ipParser.getipSaddress(ipPacket6);
								
								
								if (srcType.equals("arp") && srcType2 == 2054){
									if (saddress.equals(arpsIPAddr)){
										System.out.println(arpPacket6);
									}
									continue;
								}
								
								
								if (srcType.equals("ip") && srcType2 == 2048){	
									if (saddress.equals(ipIPS)){
										System.out.println(ipPacket6);
									}
									continue;
								}
							}
						}						
					}
					break;
		
				case "-dst": //Print only packets with destination address equal to daddress
					String num5 = args[index+1];
					int dstNum = Integer.parseInt(num5);
					String destType = args[index+2];
					String daddress = args[index+3];
					String drule = args[index+4];
					daddress = daddress +".";
					
					for (int j = 0; j < dstNum; j++){
						byte[] dstPacket = EtherParser.etherParser(EtherParser.packetCatcher());
						if (dstPacket != null){
							if(packetEvaluator.PacketEvaluator(dstPacket, drule)){
								byte[] ipPacket6 = ipParser.IPparser(dstPacket);
								byte[] arpPacket6 = arpParser.ARPparser(dstPacket);			
								int dstType2 = EtherParser.getType(dstPacket);						
								String ipIPD =ipParser.getipDaddress(ipPacket6);
								String arpTargetIP =arpParser.gettargetIPAddr(arpPacket6);
								
								if (destType.equals("arp") && dstType2 == 2054){
									if (daddress.equals(arpTargetIP)){								
										System.out.println(arpPacket6);
									}
									continue;
								}
							
								
								if (destType.equals("ip") && dstType2 == 2048){	
									if (daddress.equals(ipIPD)){
										System.out.println(ipPacket6);							
									}
									continue;
								}
							}
						}						
					}
					break;
				
				case "-sord": //Print only packets where the source address matches saddress or the destination address matches daddress
					String num6 = args[index+1];
					int sordNum = Integer.parseInt(num6); 
					String sordType = args[index+2];
					String saddress2 = args[index+3];
					saddress2 = saddress2 +".";
					String daddress2 = args[index+4];
					daddress2 = daddress2 +".";
					String orrule = args[index+5];
					for (int j = 0; j < sordNum; j++){
						byte[] sordPacket = EtherParser.etherParser(EtherParser.packetCatcher());
						if (sordPacket != null){
							if(packetEvaluator.PacketEvaluator(sordPacket, orrule)){
								byte[] ipPacket6 = ipParser.IPparser(sordPacket);
								byte[] arpPacket6 = arpParser.ARPparser(sordPacket);						
								String ipIPS2 =ipParser.getipSaddress(ipPacket6);
								String arpsIPAddr2 =arpParser.getsIPAddr(arpPacket6);
								String ipIPD2 =ipParser.getipDaddress(ipPacket6);
								String arpTargetIP2 =arpParser.gettargetIPAddr(arpPacket6);
								int sordType2 = EtherParser.getType(sordPacket);						
							
								if (sordType.equals("arp") && sordType2 == 2054){
									if (saddress2.equals((arpsIPAddr2)) || daddress2.equals((arpTargetIP2))){
										System.out.println(arpPacket6);
									}
								}
								
								if (sordType.equals("ip") && sordType2 == 2048){	
									if (saddress2.equals((ipIPS2)) || daddress2.equals((ipIPD2))){
										System.out.println(ipPacket6);
									}
								}
							}
						}						
					}
					break;
					
				case "-sandd": //Print only packets where the source address matches saddress and the
					           //destination address matches daddress
					String num7 = args[index+1];
					int sanddNum = Integer.parseInt(num7); 
					String sanddType = args[index+2];
					String saddress3 = args[index+3];
					saddress3 = saddress3 +".";
					String daddress3 = args[index+4];
					daddress3 = daddress3 +".";					
					String andrule = args[index+5];
					for (int j = 0; j < sanddNum; j++){
						byte[] sanddPacket = EtherParser.etherParser(EtherParser.packetCatcher());
						if (sanddPacket != null){
							if(packetEvaluator.PacketEvaluator(sanddPacket, andrule)){
								byte[] ipPacket5 = ipParser.IPparser(sanddPacket);
								byte[] arpPacket5 = arpParser.ARPparser(sanddPacket);						
								String ipIPS3 =ipParser.getipSaddress(ipPacket5);
								String arpsIPAddr3 =arpParser.getsIPAddr(arpPacket5);
								String ipIPD3 =ipParser.getipDaddress(ipPacket5);
								String arpTargetIP3 =arpParser.gettargetIPAddr(arpPacket5);
								int sanddType2 = EtherParser.getType(sanddPacket);
								
								if (sanddType.equals("arp") && sanddType2 == 2054){
									if (saddress3.equals(arpsIPAddr3) && daddress3.equals(arpTargetIP3)){
										System.out.println(ipPacket5);
									}
								}
								
								if (sanddType.equals("ip") && sanddType2 == 2048){	
									if (saddress3.equals(ipIPS3) && daddress3.equals(ipIPD3)){
										System.out.println(arpPacket5);
									}
								}
							}
						}						
					}
					break;
					
				case "-sport": //Print only packets where the source port is in the range port1-port2
					
					String num8 = args[index+1];
					int sportNum = Integer.parseInt(num8); 
					String sportType = args[index+2];
					String sporta = args[index+3];
					int sport1 = Integer.parseInt(sporta);
					String sportb = args[index+4];
					int sport2 = Integer.parseInt(sportb);
					String sportrule = args[index+5];
					for (int j = 0; j < sportNum; j++){
						byte[] etherPacket4 = EtherParser.etherParser(EtherParser.packetCatcher());
						if (etherPacket4 != null){
							if(packetEvaluator.PacketEvaluator(etherPacket4, sportrule)){
								byte[] ipPacket4 = ipParser.IPparser(etherPacket4);
								String sportType2 = ipParser.getprot(ipPacket4);	
								byte[] tcpPacket4 = tcpParser.TCPparser(ipPacket4);
								byte[] udpPacket4 = udpParser.UDPparser(ipPacket4);
								int tcpSourcePort=tcpParser.gettcpSport(tcpPacket4);
								int udpSourcePort=udpParser.getudpSport(udpPacket4); 
								
								if (sportType.equals("udp") && sportType2.equals("This is a UDP packet")){
									if (sport1 >= udpSourcePort && sport2 >= udpSourcePort){ 
										System.out.println(udpPacket4);
									}
								}
								if (sportType.equals("tcp") && sportType2.equals("This is a TCP packet")){
									if (sport1 >= tcpSourcePort && sport2 >= tcpSourcePort){ 
										System.out.println(tcpPacket4);
									}
								}
							}
						}						
					}
					break;
					
				case "-dport": //Print only packets where the destination port is in the range port1-port
					String num9 = args[index+1];
					int dportNum = Integer.parseInt(num9); 
					String dportType = args[index+2];
					String dporta = args[index+3];
					int dport1 = Integer.parseInt(dporta);
					String dportb = args[index+4];
					int dport2 = Integer.parseInt(dportb);					
					String dportrule = args[index+5];
					for (int j = 0; j < dportNum; j++){
						byte[] etherPacket3 = EtherParser.etherParser(EtherParser.packetCatcher());
						if (etherPacket3 != null){
							if(packetEvaluator.PacketEvaluator(etherPacket3, dportrule)){
								byte[] ipPacket3 = ipParser.IPparser(etherPacket3);
								String dportType2 = ipParser.getprot(ipPacket3);	
								byte[] tcpPacket3 = tcpParser.TCPparser(ipPacket3);
								byte[] udpPacket3 = udpParser.UDPparser(ipPacket3);
								int tcpDestPort2=tcpParser.gettcpDport(tcpPacket3);
								int udpDestPort2=udpParser.getudpDport(udpPacket3); 
								
								if (dportType.equals("udp") && dportType2.equals("This is a UDP packet")){
									if (dport1 >= udpDestPort2 && dport2 >= udpDestPort2){ 
										System.out.println(udpPacket3);
									}
								}
								
								if (dportType.equals("tcp") && dportType2.equals("This is a TCP packet")){
									if (dport1 >= tcpDestPort2 && dport2 >= tcpDestPort2){ 
										System.out.println(tcpPacket3);
									}
								}
							}
						}						
					}
					break;
			}
			index++;
		}
	}
}
