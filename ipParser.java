import java.util.Arrays;

public class ipParser{
	
	
	
	public static byte[] IPparser(byte[] etherPacket){
		byte[] ipPacket = null;
		byte[] etherType = Arrays.copyOfRange(etherPacket, 12, 14);
		if (Lib.byteArrayToInt(etherType) == 2048){ //ARP 0x800
			ipPacket = Lib.copyByteArray(etherPacket, 14); //from 14 to end, header end at 37
		}
		return ipPacket;
	}
	
	public static String getIPHeader(byte[] ipPacket){
		int version = getversion(ipPacket);
		int IHL = getIHL( ipPacket);
		int typeS = gettos( ipPacket);
		int totLen = gettotalLength( ipPacket);
		int IDS = getID( ipPacket);
		int flags = getflags( ipPacket);
		int fragOffset = getfragOffset( ipPacket);
		int TTL = gettimeToLive( ipPacket);
		String prot = getprot( ipPacket);
		int cs = getActualChecksum( ipPacket);
		String ipS = getipSaddress( ipPacket);
		String ipD = getipDaddress( ipPacket);
		
		String toPrint = "Version: "+version+"\n"
				+"IP Header Length: "+IHL+"\n"
				+"Type of Service: "+typeS+"\n"
				+"Total Length: "+totLen+"\n"
				+"ID: "+IDS+"\n"
				+"Flags: "+flags+"\n"
				+"Fragment Offset: "+fragOffset+"\n"
				+"Time To Live: "+TTL+"\n"
				+"Protocol Type: "+prot+"\n"
				+"Header Checksum: "+cs+"\n"
				+"Source IP Address: "+ipS+"\n"
				+"Destination IP Address: "+ipD+"\n";
		return toPrint;		
	}
	
	public static String getIPPacket(byte[] ipPacket){
		int version = getversion(ipPacket);
		int IHL = getIHL( ipPacket);
		int typeS = gettos( ipPacket);
		int totLen = gettotalLength( ipPacket);
		int IDS = getID( ipPacket);
		int flags = getflags( ipPacket);
		int fragOffset = getfragOffset(ipPacket);
		int TTL = gettimeToLive( ipPacket);
		String prot = getprot( ipPacket);
		int cs = getActualChecksum( ipPacket);
		String ipS = getipSaddress( ipPacket);
		String ipD = getipDaddress( ipPacket);
		byte[] pl = getIpPayload(ipPacket);
		String payload = Lib.getString(pl);
		
		String toPrint = "Version: "+version+"\n"
				+"IP Header Length: "+IHL+"\n"
				+"Type of Service: "+typeS+"\n"
				+"Total Length: "+totLen+"\n"
				+"ID: "+IDS+"\n"
				+"Flags: "+flags+"\n"
				+"Fragment Offset: "+fragOffset+"\n"
				+"Time To Live: "+TTL+"\n"
				+"Protocol Type: "+prot+"\n"
				+"Header Checksum: "+cs+"\n"
				+"Source IP Address: "+ipS+"\n"
				+"Destination IP Address: "+ipD+"\n"
				+"Payload: "+payload+"\n";				
		return toPrint;		
	}

	public static int getversion(byte[] ipPacket){
		int version = ((ipPacket[0] >> 4) & 0x0f);
		return version;
	}
	
	public static int getIHL(byte[] ipPacket){
		int IHL = (ipPacket[0] & 0x0f);
		return IHL;
	}
	
	public static int gettos(byte[] ipPacket){
		byte tos = ipPacket[1];
		int typeS = tos;
		return typeS;
	}
	
	public static int gettotalLength(byte[] ipPacket){
		byte[] totalLength = Arrays.copyOfRange(ipPacket, 2, 4);
		int totLen = Lib.byteArrayToInt(totalLength);
		return totLen;
	}
	
	public static int getID(byte[] ipPacket){
		byte[] ID = Arrays.copyOfRange(ipPacket, 4, 6);
		int IDS = Lib.byteArrayToInt(ID);
		return IDS;
	}
	
	public static int getflags(byte[] ipPacket){
		int flags = ((ipPacket[6] & 0xff) >> 5);
		return flags;
	}
	
	public static String getFlagsType(byte[] ipPacket){
		int flags = getflags(ipPacket);
		int fragOffset = getfragOffset(ipPacket);
		String flagsType = "";
		if (flags == 0 && fragOffset != 0){
			flagsType = "LF";
		}
		if (flags == 0 && fragOffset == 0){
			flagsType = "UF";
		}
		if (flags == 1 && fragOffset != 0){
			flagsType = "MF";
		}
		if (flags == 1 && fragOffset == 0){
			flagsType = "MF";
		}
		if (flags == 2 && fragOffset == 0){
			flagsType = "DF";
		}
		return flagsType;
	}
	
	public static int getfragOffset(byte[] ipPacket){
		int sh = (int)ipPacket[6];
		sh <<= 8;
		int fragOffset = (int) ((int)(sh | ipPacket[7]) & 0x1FFF);
		return fragOffset;
	}
	
	public static int gettimeToLive(byte[] ipPacket){
		byte timeToLive = ipPacket[8];
		int TTL = timeToLive & 0x7f;
		return TTL;
	}
	
	public static String getprot(byte[] ipPacket){
		byte prot = ipPacket[9];
		int p = prot;
		String ps = "";
		if (p == 6){ 
			ps = "This is a TCP packet";
		}
		else if (p == 17) {
			ps = "This is a UDP packet";
		}
		else if (p == 1){ 
			ps = "This is a ICMP packet";
		}else{
			ps = Integer.toString(p);
		}
		return ps;
	}
	
	public static int getIpChecksum(byte[] ipPacket){
		byte[] headChecksum = Arrays.copyOfRange(ipPacket, 10, 12);
		int cs = Lib.byteArrayToInt(headChecksum);
		return cs;
	}
	
	public static int getActualChecksum(byte[] ipPacket){
		byte[] header = Arrays.copyOfRange(ipPacket, 0, 20);
		int actualChecksum = calculateChecksum.getChecksum(header);
		return actualChecksum;
	}
	
	public static String getipSaddress(byte[] ipPacket){
		byte[] ipSaddress = Arrays.copyOfRange(ipPacket, 12, 16);
		String ipS = Lib.getIPAddress(Lib.getString(ipSaddress).replaceAll("\\s+", ""));
		return ipS;
	}
	
	public static String getipDaddress(byte[] ipPacket){
		byte[] ipDaddress = Arrays.copyOfRange(ipPacket, 16, 20);
		String ipD = Lib.getIPAddress(Lib.getString(ipDaddress).replaceAll("\\s+", ""));
		return ipD;
	}
	
	public static byte[] getoptions(byte[] ipPacket){
		byte[] options = Arrays.copyOfRange(ipPacket, 20, 24);
		//modify options here
		return options;
	}
	
	public static byte[] getIpPayload(byte[] ipPacket){
		int IHL = getIHL(ipPacket);
		int totalLen = gettotalLength(ipPacket);
		byte[] payload = null;
		payload = Arrays.copyOfRange(ipPacket, (IHL*4), totalLen);
		return payload;
	}
}