import java.util.Arrays;

public class arpParser{
	
	public static byte[] ARPparser(byte[] etherPacket) {
		byte [] etherType = Arrays.copyOfRange(etherPacket, 12, 14);
		byte[] arpPacket=null;
		if (Lib.byteArrayToInt(etherType) == 2054){ //ARP 0x806
			arpPacket = Lib.copyByteArray(etherPacket, 14); //from 14 to end, header end at 37
		}
		return arpPacket;
	}
	
	//public static String arpPacketReassembler(byte[] fragment, int fragOffset){***}
	
	public static String getARPHeader(byte[] arpPacket){
		String hardw = gethardwType(arpPacket);
		String prot = getprotType( arpPacket);
		int len = gethardwAddrLen( arpPacket);
		int protLen = getprotAddrLen( arpPacket);
		int op = getopCode( arpPacket);
		String sHard = getsHardAddr( arpPacket);
		String sIp = getsIPAddr( arpPacket);
		String targetHard = gettargetHardAddr( arpPacket);
		String tIp = gettargetIPAddr( arpPacket);
		String toPrint = "Hardware Type: "+hardw+"\n"
				+ "Protocol Type: "+prot+"\n"
				+ "Hardware Address Length: "+len+"\n"
				+ "Protocol Address Length: "+protLen+"\n"
				+ "Option Code: "+op+"\n"
				+ "Source Hardware Address: "+sHard+"\n"
				+ "Source IP Address: "+sIp+"\n"
				+ "Target Hardware Address: "+targetHard+"\n"
				+ "Target IP Address: "+tIp+"\n";
		return toPrint;
	}
	
	public static String getARPPacket(byte[] arpPacket){
		String hardw = gethardwType(arpPacket);
		String prot = getprotType( arpPacket);
		int len = gethardwAddrLen( arpPacket);
		int protLen = getprotAddrLen( arpPacket);
		int op = getopCode( arpPacket);
		String sHard = getsHardAddr( arpPacket);
		String sIp = getsIPAddr( arpPacket);
		String targetHard = gettargetHardAddr( arpPacket);
		String tIp = gettargetIPAddr( arpPacket);
		byte[] payload = Lib.copyByteArray(arpPacket, 28);
		String toPrint = "Hardware Type: "+hardw+"\n"
				+ "Protocol Type: "+prot+"\n"
				+ "Hardware Address Length: "+len+"\n"
				+ "Protocol Address Length: "+protLen+"\n"
				+ "Option Code: "+op+"\n"
				+ "Source Hardware Address: "+sHard+"\n"
				+ "Source IP Address: "+sIp+"\n"
				+ "Target Hardware Address: "+targetHard+"\n"
				+ "Target IP Address: "+tIp+"\n"
				+"Payload: "+ Lib.getString(payload);
		return toPrint;
	}
	
	public static String gethardwType(byte[] arpPacket) {		
		byte[] hardwType = Arrays.copyOfRange(arpPacket, 0, 2);
		String hardw = Lib.getString(hardwType);
		return hardw;
	}
	
	public static String getprotType(byte[] arpPacket) {		
		byte[] protType = Arrays.copyOfRange(arpPacket, 2, 4);
		String prot = Lib.getString(protType);
		return prot;
	}
	
	public static int gethardwAddrLen(byte[] arpPacket) {		
		byte hardwAddrLen = arpPacket[4];
		int len = hardwAddrLen;
		return len;
	}
	
	public static int getprotAddrLen(byte[] arpPacket) {
		byte protAddrLen = arpPacket[5];
		int len = protAddrLen;
		return len;
	}
	
	public static int getopCode(byte[] arpPacket) {	
		byte [] opCode = Arrays.copyOfRange(arpPacket, 6, 8);
		int op = Lib.byteArrayToInt(opCode);
		return op;
	}
	
	public static String getsHardAddr(byte[] arpPacket) {	
		byte [] sHardAddr = Arrays.copyOfRange(arpPacket, 8, 14);
		String sHard = Lib.getString(sHardAddr);
		sHard = sHard.replaceAll(" ", ":");
		return sHard;
	}
	
	public static String getsIPAddr(byte[] arpPacket) {	
		byte [] sIPAddr = Arrays.copyOfRange(arpPacket, 14, 18);
		String sIp = Lib.getIPAddress(Lib.getString(sIPAddr).replaceAll("\\s+", ""));
		return sIp;
	}
	
	public static String gettargetHardAddr(byte[] arpPacket) {	
		byte [] targetHardAddr = Arrays.copyOfRange(arpPacket, 18, 24);
		String targetHard = Lib.getString(targetHardAddr);
		targetHard = targetHard.replaceAll(" ", ":");
		return targetHard;
	}
	
	public static String gettargetIPAddr(byte[] arpPacket) {
		byte [] targetIPAddr = Arrays.copyOfRange(arpPacket, 24, 28);
		String tIp = Lib.getIPAddress(Lib.getString(targetIPAddr).replaceAll("\\s+", ""));
		return tIp;
	}
}