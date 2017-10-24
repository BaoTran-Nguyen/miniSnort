import java.io.*;

public class packetEvaluator{
	public static boolean PacketEvaluator(byte[] packet, String rule) throws IOException{
		String packetStatus = null;
		int type = EtherParser.getType(packet);
		String prot = ipParser.getprot(packet);
		String sourceIP;
		String destIP;
		int sourcePort = 0;
		int destPort = 0;
		byte[] ipPacket = null;
		byte[] arpPacket = null;
		if (type == 2048){
			ipPacket = ipParser.IPparser(packet);
			sourceIP = ipParser.getipSaddress(ipPacket);
			destIP = ipParser.getipDaddress(ipPacket);
			if (prot.equals("This is a TCP packet")){
				sourcePort = tcpParser.gettcpSport(ipPacket);
			}
			
			if (prot.equals("This is a UDP packet")){
				sourcePort = udpParser.getudpSport(ipPacket);
			}
			packetStatus = checkPacketAgainstRules(sourceIP, sourcePort, destIP, destPort, rule);
			
			if (packetStatus.equals("Good to go!")){
				return true;
			}else{
				logPacket(packetStatus, ipPacket, "log.txt");
				return checkOption(sourceIP, destIP, packetStatus, ipPacket);
			}			
		}
		
		if (type == 2054){
			arpPacket = arpParser.ARPparser(packet);
			sourceIP = arpParser.getsIPAddr(arpPacket);
			destIP = arpParser.gettargetIPAddr(arpPacket);
			packetStatus = checkPacketAgainstRules(sourceIP, destIP, arpPacket, rule);
			if (packetStatus.equals("Good to go!")){
				return true;
			}else{
				logPacket(packetStatus, arpPacket, "log.txt");				
				return checkOption(sourceIP, destIP, packetStatus, arpPacket);
			}
		}else{
			return false;
		}
	}
	
	public static void logPacket(String packetStatus, byte[] packet, String logname) throws IOException{
		StringBuilder log = new StringBuilder();
		BufferedWriter bw = null;
		try{
			bw = new BufferedWriter(new FileWriter(logname, true));
			log.append(packetStatus);
			log.append("\n");
			log.append(Lib.getString(packet));
			log.append("\n");
			bw.write(log.toString());
		}catch(Exception e){
			e.printStackTrace();
		}finally{
			if(bw!=null)
				bw.close();
			if(bw!=null)
				bw.close();
		}
	}
	
	public static String checkPacketAgainstRules(String sourceIP, int sourcePort, String destIP, int destPort, String ruleDoc){
		String[] ruleSet = rulesParser.readRules(ruleDoc);		
		String action, rulesIP, ruledIP;
		String rulesPort, ruledPort;
		for (int i = 0; i < ruleSet.length;i++){
			String rule = ruleSet[i];
			action = rulesParser.getAction(rule);
			rulesIP = rulesParser.getSourceIP(rule)+".";
			ruledIP = rulesParser.getDestIP(rule)+".";
			rulesPort = rulesParser.getSourcePort(rule);
			ruledPort = rulesParser.getDestPort(rule);
			
			if(sourceIP.equals(rulesIP) || rulesIP.equals("any")){
				if(Integer.toString(sourcePort).equals(rulesPort) || rulesPort.equals("any")){					
					if(destIP.equals(ruledIP) || rulesIP.equals("any")){						
						if(Integer.toString(destPort).equals(ruledPort) || ruledPort.equals("any")){
							if(action.equalsIgnoreCase("Alert")){
								return ruleSet[i];
							}else{
								return "Good to go!";
							}
						}else{
							continue;
						}
					}else{
						continue;
					}
				}else{
					continue;
				}
			}else{
				continue;
			}
		}	
		return "Good to go!"; //MAY NEED TO CHECK LOGIC HERE
	}
	
	public static String checkPacketAgainstRules(String sourceIP, String destIP, byte[] arpPacket, String ruleDoc){
		String[] ruleSet = rulesParser.readRules(ruleDoc);
		String action, rulesIP, ruledIP;
		
		for (int i = 0; ruleSet.length >= 1;i++){
			String rule = ruleSet[i];
			action = rulesParser.getAction(rule);
			rulesIP = rulesParser.getSourceIP(rule)+".";
			ruledIP = rulesParser.getDestIP(rule)+".";
			
			if(sourceIP.equals(rulesIP) || rulesIP.equals("any")){
				if(destIP.equals(ruledIP) || rulesIP.equals("any")){
					if(action.equalsIgnoreCase("Alert")){						
						return ruleSet[i];
					}else{
						return "Good to go!";
					}					
				}else{
					continue;
				}
			}else{
				continue;
			}
		}
		return "Good to go!"; //MAY NEED TO CHECK LOGIC HERE
	}
	
	public static boolean checkOption(String srcIP, String destIP, String rule, byte[] packet) throws IOException{
		String option = rulesParser.getOption(rule);
		String[] arr = option.split("; ");
		byte[] tcpPacket = tcpParser.TCPparser(packet);
		byte[] icmpPacket = icmpParser.ICMPparser(packet);
		for (int i = 0; i < arr.length; i++){
			String[] keyArr = arr[i].split(":");
			String keyword = keyArr[0].replaceAll("[()]", "");			
			String desc = keyArr[1].replaceAll("[()]", "");
			desc.replaceAll("[\"]", "");
			if (keyword.equals("msg")){
				System.out.println(desc);
				continue;
			}
			if (keyword.equals("logto")){
				logPacket(rule, packet, desc);
				continue;
			}
			if (keyword.equals("ttl")){
				if (ipParser.gettimeToLive(packet) == Integer.parseInt(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("tos")){
				if (ipParser.gettos(packet) == Integer.parseInt(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("id")){
				if (ipParser.getID(packet) == Integer.parseInt(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("fragoffset")){
				if (ipParser.getfragOffset(packet) == Integer.parseInt(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("ipoption")){
				String ipOp = Lib.getString(ipParser.getoptions(packet));
				String[] descArr = desc.split("|");
				for(int j = 0; j < descArr.length; j++){
					if(ipOp.equals(descArr[i])){
						return false;
					}else{
						continue;
					}
				}
				continue;
			}
			if (keyword.equals("fragbits")){
				if (ipParser.getFlagsType(packet).equalsIgnoreCase(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("dsize")){
				if (ipParser.getIpPayload(packet).length == Integer.parseInt(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("flags")){//tcp flags?
				if (ipParser.getflags(packet) == Integer.parseInt(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("seq")){
				if (tcpParser.getseqNum(tcpPacket) == Integer.parseInt(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("ack")){
				if (tcpParser.getackNum(tcpPacket) == Integer.parseInt(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("itype")){
				if (icmpParser.geticmpType(icmpPacket) == Integer.parseInt(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("icode")){
				if (icmpParser.getcode(icmpPacket) == Integer.parseInt(desc)){
					return false;
				}else{
					continue;
				}
			}
			if (keyword.equals("content")){
				String ipPL = Lib.getString(ipParser.getIpPayload(packet));
				String[] descArr = desc.split("|");
				for(int j = 0; j < descArr.length; j++){
					if(ipPL.equals(descArr[i])){
						return false;
					}else{
						continue;
					}
				}
			}
			if (keyword.equals("sameip")){
				if (srcIP.equals(destIP)){
					return false;
				}else{
					continue;
				}
			}
		}
		return true;
	}
}