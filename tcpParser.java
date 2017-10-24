import java.util.Arrays;

public class tcpParser{
	public static byte[] TCPparser(byte[] ipPacket) {
		byte prot = ipPacket[9];
		byte[] tcpPacket = Lib.copyByteArray(ipPacket, 20);
		if (Byte.toString(prot).equals("6")){ //tcp 0x06
			tcpPacket = ipParser.getIpPayload(ipPacket);
		}
		return tcpPacket;
	}
	public static String getTCPHeader(byte[] tcpPacket){
		int ipS = gettcpSport( tcpPacket);
		int ipD = gettcpDport( tcpPacket);
		int seq = getseqNum( tcpPacket);
		int ack = getackNum( tcpPacket);
		int dataOffset = getdataOffset( tcpPacket);
		int r = getreserved( tcpPacket);
		int win = getwindow( tcpPacket);
		int cs = gettcpChecksum( tcpPacket);
		int urg = geturgPointer(tcpPacket);
		String toPrint = "Source Port: "+ipS+"\n"
				+"Destination Port: "+ipD+"\n"
				+"Sequence Number: "+seq+"\n"
				+"Ack Number: "+ack+"\n"
				+"Offset: "+dataOffset+"\n"
				+"Reserved: "+r+"\n"
				+"Window Size: "+win+"\n"
				+"Checksum: "+cs+"\n"
				+"Urgent Pointer: "+urg+"\n";
		return toPrint;
	}
	
	public static String getTCPPacket(byte[] tcpPacket){
		int ipS = gettcpSport( tcpPacket);
		int ipD = gettcpDport( tcpPacket);
		int seq = getseqNum( tcpPacket);
		int ack = getackNum( tcpPacket);
		int dataOffset = getdataOffset( tcpPacket);
		int r = getreserved( tcpPacket);
		int win = getwindow( tcpPacket);
		int cs = gettcpChecksum( tcpPacket);
		int urg = geturgPointer(tcpPacket);
		byte[] payload = Lib.copyByteArray(tcpPacket, 20);
		String toPrint = "Source Port: "+ipS+"\n"
				+"Destination Port: "+ipD+"\n"
				+"Sequence Number: "+seq+"\n"
				+"Ack Number: "+ack+"\n"
				+"Offset: "+dataOffset+"\n"
				+"Reserved: "+r+"\n"
				+"Window Size: "+win+"\n"
				+"Checksum: "+cs+"\n"
				+"Urgent Pointer: "+urg+"\n"
				+"Payload: "+ Lib.getString(payload);
		return toPrint;
	}
	
	public static int gettcpSport(byte[] tcpPacket){
		byte [] ipSport = Arrays.copyOfRange(tcpPacket, 0, 2);
		int ipS = Lib.byteArrayToInt(ipSport);
		return ipS;
	}
	
	public static int gettcpDport(byte[] tcpPacket){		
		byte [] ipDport = Arrays.copyOfRange(tcpPacket, 2, 4);
		int ipD = Lib.byteArrayToInt(ipDport);
		return ipD;
	}
	
	public static int getseqNum(byte[] tcpPacket){		
		byte [] seqNum = Arrays.copyOfRange(tcpPacket, 4, 8);
		int seq = Lib.byteArrayToInt(seqNum);
		return seq;
	}
	
	public static int getackNum(byte[] tcpPacket){	
		byte [] ackNum = Arrays.copyOfRange(tcpPacket, 8, 12);
		int ack = Lib.byteArrayToInt(ackNum);
		return ack;
	}
	
	public static int getdataOffset(byte[] tcpPacket){	
		int dataOffset = ((tcpPacket[12] & 0x0f) >> 4);
		return dataOffset;
	}
	
	public static int getreserved(byte[] tcpPacket){	
		int reserved = ((tcpPacket[12] & 0x0f)   + tcpPacket[13]);
		int r = reserved;
		return r;
	}
	
	public static int getwindow(byte[] tcpPacket){		
		byte [] window = Arrays.copyOfRange(tcpPacket, 14, 16);
		int win = Lib.byteArrayToInt(window);
		return win;
	}
	
	public static int gettcpChecksum(byte[] tcpPacket){		
		byte [] tcpChecksum = Arrays.copyOfRange(tcpPacket, 16, 18);
		int cs = Lib.byteArrayToInt(tcpChecksum);
		return cs;
	}
	
	public static int geturgPointer(byte[] tcpPacket){
		byte [] urgPointer = Arrays.copyOfRange(tcpPacket, 18, 20);
		int urg = Lib.byteArrayToInt(urgPointer);
		return urg;
	}
	
	public static byte[] gettcpOptions(byte[] tcpPacket){
		byte[] tcpOptions = Arrays.copyOfRange(tcpPacket, 20, 24);
		//modify options here
		return tcpOptions;
	}
}