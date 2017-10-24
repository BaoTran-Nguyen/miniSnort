import java.util.*;

public class EtherParser {
	static HashMap<String, ArrayList<byte[]>> map = new HashMap<String, ArrayList<byte[]>>();
	static HashMap<String, Integer> payloadLenMap = new HashMap<>();
	static HashMap<String, byte[]> headerMap = new HashMap<>();
	static HashMap<String, byte[]> etherheaderMap = new HashMap<>();
	static HashMap<String, Integer> expectTotalLenMap = new HashMap<>();
	static HashMap<String, Long> timeStampMap = new HashMap<>();
	//call packetCatcher if catching traffic from the network
	public static byte[] packetCatcher() {
		byte[] etherPacket = null;
		SimplePacketDriver driver= new SimplePacketDriver();
		String[] adapters=driver.getAdapterNames(); 		
		for (int i=0; i< adapters.length; i++) 
		driver.openAdapter(adapters[0]);
		etherPacket = driver.readPacket();
		return etherPacket;
	}
	
	//call etherParser if reading from a file
	public static byte[] etherParser(byte[] etherPacket){
		byte[] etherType = Arrays.copyOfRange(etherPacket, 12, 14);
		byte[] ipPacket = Lib.copyByteArray(etherPacket, 14);
		byte[] packet = null;
		if (Lib.byteArrayToInt(etherType) == 2048){ //IP 0x800
			int flags = ipParser.getflags(ipPacket);
			int fragOffset = ipParser.getfragOffset(ipPacket);	
			if (flags == 1  || fragOffset != 0){ //if fragment, send to reassembly and start over				
				etherPacket = PacketReassembler(etherPacket);
				if (etherPacket != null){
					packet = etherPacket;
					return packet;
				}
			} 
			else if (flags == 0 && fragOffset == 0){
				return etherPacket;
			}else{
				return null;
			}
		}
		if (Lib.byteArrayToInt(etherType) == 2054){//if arp
			int sid = 0;
			Lib.assemblePacket(etherType, sid);
			return etherPacket;	
		}else{
			return null;
		}
	}
	
	@SuppressWarnings("rawtypes")
	public static byte[] PacketReassembler(byte[] etherfragment){
		byte[] fragment = Lib.copyByteArray(etherfragment, 14);
		ArrayList<byte[]> arr = new ArrayList<>();
		Queue<ByteArray> sortedQueue =  new PriorityQueue<>(11, comp);
		//initializing
		byte[] fragmentList;
		byte[] assembledPayload;
		byte[] header; 
		int currPayloadLen = 0;
		int expectPayloadLen = 0;
		int sid = 0;
		boolean isGapped = false;
		byte[] etherHeader = Arrays.copyOfRange(etherfragment, 0, 14);
		//key
		int id = ipParser.getID(fragment);
		String sIpAddress = ipParser.getipSaddress(fragment);
		String lIpAddress = ipParser.getipDaddress(fragment);
		String ID = Integer.toString(id);
		String key = sIpAddress+lIpAddress+ID;
		
		//int flags = getflags(fragmentS);
		String flagsType =ipParser. getFlagsType(fragment);
		byte[] payload = ipParser.getIpPayload(fragment);
		
		//preprocessing
		int actualChecksum = ipParser.getActualChecksum(fragment);
		int fragOffset = ipParser.getfragOffset(fragment)*8;
		boolean isOverSized = false;
		boolean badChecksum = false;
		boolean isOverlapped = false;
		boolean badOffset = false;			
		
		if (fragOffset == 1) {
			badOffset = true;				
		}
		
		if (actualChecksum != 0) {
			badChecksum = true;
		}
		
		if (fragment.length > 64000) {
			isOverSized = true;
			sid = 3;
		}
		
		if (badChecksum || badOffset){
			System.out.println(badOffset);
			System.out.println(badChecksum);
			System.out.println(isOverSized);
			return null;
		}
		
		//execution body
		else{
			if (!map.containsKey(key)){
				
			    ArrayList<byte[]> ar = new ArrayList<byte[]>();
				
				int payloadLen = payload.length;
				payloadLenMap.put(key, payloadLen);
				
	            ar.add(fragment);
	            map.put(key, ar);
	            
	            header = Arrays.copyOfRange(fragment, 0, 20); //may need to adjust to adapt to options
	            headerMap.put(key, header);	 
	            
	            etherheaderMap.put(key, etherHeader);
	            for (int i = 0; i < timeStampMap.size(); i++){
					Iterator it = timeStampMap.entrySet().iterator();
	            	    while (it.hasNext()) {
	            	        HashMap.Entry pair = (HashMap.Entry)it.next();
	            	        long timeStamp = (long) pair.getValue();
	            	        if ((timeStamp + 60000) <= System.currentTimeMillis())
	            	        	it.remove(); // avoids a ConcurrentModificationException 
	            	    }
	            }
	            long timeStamp = System.currentTimeMillis();
	            timeStampMap.put(key, timeStamp);
	            
	            if (flagsType.equals("LF")){					
					expectPayloadLen = (fragOffset) + payload.length;
					expectTotalLenMap.put(key, expectPayloadLen);
				}
	            
			}else{
				//add fragment to map
				map.get(key).add(fragment);
				arr = (map.get(key)); 
				
				for (int i = 0; i < arr.size(); i++){
					byte[] b = arr.get(i);
					sortedQueue.add(new ByteArray(b));
				}
				//check  if packet is complete
				currPayloadLen = Lib.getCurrLen(sortedQueue);
				if (flagsType.equals("LF")){					
					expectPayloadLen = (fragOffset) + payload.length;
					expectTotalLenMap.put(key, expectPayloadLen);
				} 

				if(expectTotalLenMap.containsKey(key)) {
					expectPayloadLen = expectTotalLenMap.get(key);
				}
				isGapped = Lib.checkForGap(sortedQueue);

				//if complete
				if (expectPayloadLen == currPayloadLen && !isGapped){

					isOverlapped = Lib.checkForOverlap(sortedQueue);
					if(!isOverlapped) sid = 1;
					if(isOverlapped) sid = 2;
					
					fragmentList = Lib.getListofFragments(sortedQueue);	

					assembledPayload = Lib.getPayloadFromQueue(sortedQueue, expectPayloadLen);

					header = headerMap.get(key);
					//change total length
					int totLen = assembledPayload.length + 20; //may need to adjust if options
					header[2] = (byte) ((totLen >> 8) & 0xFF);
					header[3] = (byte) (totLen & 0xFF);
					//change header flags and offset
					header[6] = 0;
					header[7] = 0;
					byte[] assembledPacket = Lib.assemblePacket(etherHeader, header, assembledPayload, sid, fragmentList);
					map.remove(sortedQueue);
					return assembledPacket;
				}
			}
		}
		return null;
	}
	
	public static String getEtherHeader(byte[] etherPacket){
		String dstMAC = getdst(etherPacket);
		String srcMAC = getsrc(etherPacket);
		int t = getType(etherPacket);
		String type = "";
		if (t == 2054) type = "This is an ARP packet";
		if (t == 2048) type = "this is an IP packet";
		String toPrint = "MAC Destination Address: " +dstMAC+"\n"
				+"MAC Source Address: " +srcMAC+"\n"
				+"Type: "+type+"\n";
		return toPrint; 
	}
	
	public static String getEtherPacket(byte[] etherPacket){
		String dstMAC = getdst(etherPacket);
		String srcMAC = getsrc(etherPacket);
		int t = getType(etherPacket);
		String type = "";
		if (t == 2054) type = "This is an ARP packet";
		if (t == 2048) type = "this is an IP packet";
		byte[] ipPayload = ipParser.getIpPayload(Lib.copyByteArray(etherPacket, 14));
		byte[] payload = Arrays.copyOfRange(etherPacket, 14, (20+ipPayload.length));
		int sid = 0;
		byte[] fragmentList = null;
		if(etherPacket.length > (14+payload.length)){ //may need to check if sid byte is null
			sid = etherPacket[14+payload.length];
		}
		if(etherPacket.length > (15+payload.length)){
			fragmentList = Lib.copyByteArray(etherPacket, 15+payload.length);
		}
		
		String toPrint = "MAC Destination Address: " +dstMAC+"\n"
				+"MAC Source Address: " +srcMAC+"\n"
				+"Type: "+type+"\n"
				+"sid: "+sid+"\n"
				+"Payload: "+Lib.getString(payload)+"\n"
				+"Fragment List: "+Lib.getString(fragmentList)+"\n";
		return toPrint; 
	}
	
	public static Comparator<ByteArray> comp = new Comparator<ByteArray>(){		
		@Override
		public int compare(ByteArray c1, ByteArray c2) {
            return (int) (c1.getD() - c2.getD());
        }
	};
	
	public static String getdst(byte[] etherPacket){
        byte [] dst = Arrays.copyOfRange(etherPacket, 0, 6);
		String dstMAC = Lib.getString(dst);
        dstMAC = dstMAC.replaceAll(" ", ":");
		return dstMAC;
	}
	public static String getsrc(byte[] etherPacket){
		byte [] src = Arrays.copyOfRange(etherPacket, 6, 12);
		String srcMAC = Lib.getString(src);
		srcMAC = srcMAC.replaceAll(" ", ":");
		return srcMAC;
	}
	public static int getType(byte[] etherPacket){
		int type = 0;
		byte [] etherType = Arrays.copyOfRange(etherPacket, 12, 14);
		if (Lib.byteArrayToInt(etherType) == 2054){
			type = 2054;
		}
		if (Lib.byteArrayToInt(etherType) == 2048){
			type = 2048;
		}
		return type;

	}
}