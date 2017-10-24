import java.util.Arrays;

public class udpParser{
	
	public static byte[]  UDPparser(byte[] ipPacket) {
		byte prot = ipPacket[9];
		byte[] udpPacket = null;
		if (Byte.toString(prot).equals("17")){
			udpPacket = ipParser.getIpPayload(ipPacket);
		}
		return udpPacket;
	}
	public static String getUDPHeader(byte[] udpPacket){
		int udpS = getudpSport(udpPacket) ;
		int udpD = getudpDport(udpPacket);
		int len = getlength(udpPacket);
		int cs = getudpChecksum(udpPacket);
		String toPrint = "Source Port: "+udpS+"\n"
				+"Destination Port: "+udpD+"\n"
				+"Length: "+len+"\n"
				+"Checksum: "+cs+"\n";
		return toPrint;
	}
	
	public static String getUDPPacket(byte[] udpPacket){
		int udpS = getudpSport(udpPacket) ;
		int udpD = getudpDport(udpPacket);
		int len = getlength(udpPacket);
		int cs = getudpChecksum(udpPacket);
		byte[] payload = Lib.copyByteArray(udpPacket, 8);
		String toPrint = "Source Port: "+udpS+"\n"
				+"Destination Port: "+udpD+"\n"
				+"Length: "+len+"\n"
				+"Checksum: "+cs+"\n"
				+"Payload: "+ Lib.getString(payload);
		return toPrint;
	}
	
	public static int getudpSport(byte[] udpPacket) {
		byte [] udpSport = Arrays.copyOfRange(udpPacket, 0, 2);
		int udpS = Lib.byteArrayToInt(udpSport);
		return udpS;
	}
	
	public static int getudpDport(byte[] udpPacket) {
		byte [] udpDport = Arrays.copyOfRange(udpPacket, 2, 4);
		int udpD = Lib.byteArrayToInt(udpDport);
		return udpD;
	}
	
	public static int getlength(byte[] udpPacket) {
		byte [] length = Arrays.copyOfRange(udpPacket, 4, 6);
		int len = Lib.byteArrayToInt(length);
		return len;
	}
	
	public static int getudpChecksum(byte[] udpPacket) {
		byte [] udpChecksum = Arrays.copyOfRange(udpPacket, 6, 8);
		int cs = Lib.byteArrayToInt(udpChecksum);
		return cs;
	}
}