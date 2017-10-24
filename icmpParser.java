import java.util.Arrays;

public class icmpParser{
	
	public static byte[] ICMPparser(byte[] ipPacket) {
		byte prot = ipPacket[9];
		byte[] icmpPacket = null;
		if (Byte.toString(prot).equals("1")){ //icmpParser 0x01
			icmpPacket = ipParser.getIpPayload(ipPacket);
		}
		return icmpPacket;
	}
	
	public static String getICMPHeader(byte[] icmpPacket){
		int type = geticmpType(icmpPacket);
		int c = getcode(icmpPacket);
		int cs = getchecksum(icmpPacket);
		String toPrint = "Type: "+type+"\n"
				+"Code: "+c+"\n"
				+"Checksum: "+cs+"\n";
		return toPrint;
	}
	
	public static String getICMPPacket(byte[] icmpPacket){
		int type = geticmpType(icmpPacket);
		int c = getcode(icmpPacket);
		int cs = getchecksum(icmpPacket);
		byte[] payload = Lib.copyByteArray(icmpPacket, 4);
		String toPrint = "Type: "+type+"\n"
				+"Code: "+c+"\n"
				+"Checksum: "+cs+"\n"
				+"Payload: "+ Lib.getString(payload);
		return toPrint;
	}
	
	public static int geticmpType(byte[] icmpPacket) {		
		byte icmpType = icmpPacket[0];
		int type = icmpType;
		return type;
	}
	
	public static int getcode(byte[] icmpPacket) {		
		byte code = icmpPacket[1];
		int c = code;
		return c;
	}
	
	public static int getchecksum(byte[] icmpPacket) {		
		byte [] checksum = Arrays.copyOfRange(icmpPacket, 2, 4);
		int cs = Lib.byteArrayToInt(checksum);
		return cs;
	}
}