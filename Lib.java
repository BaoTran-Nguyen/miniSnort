import java.io.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.PriorityQueue;
import java.util.Queue;

public class Lib{
	
	public static ArrayList<byte[]> read(String filenameRead){
		//read in the packets from a file
		FileReader fileReader = null;
		String line;
		BufferedReader bufferedReader;
		StringBuffer stringBuffer;
		String[] packetString = null;
		ArrayList<byte[]> packetsList = new ArrayList<>();
		try {
			File file = new File(filenameRead);
			fileReader = new FileReader(file);
			bufferedReader = new BufferedReader(fileReader);
			stringBuffer = new StringBuffer();
			while ((line = bufferedReader.readLine()) != null) {
				stringBuffer.append(line);
				stringBuffer.append("\n");
				if(line.equals("")){
					stringBuffer.append("\t");
				}
			}
			String string = stringBuffer.toString();
			packetString = string.split("\t"); //read files into a string array
			for (int i = 0; i < packetString.length; i++){
				packetString[i] = packetString[i].replaceAll("\\s+", "");
				packetsList.add(hexStringToByteArray(packetString[i]));
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return packetsList;
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}

	static int getQueueSize(Queue<ByteArray> queue){
		int size = 0;
		Iterator<ByteArray> it = queue.iterator();
		while(it.hasNext()){
			byte[] a = it.next().getBytes();
			size += a.length;
		}
		return size;
	}
	
	public static byte[] getListofFragments(Queue<ByteArray> queue) {
		byte[] byteArray=new byte[getQueueSize(queue)];
		int i = 0;
		Queue<ByteArray> sortedQueue =  new PriorityQueue<>(queue);
		
		while(sortedQueue.size()>=1){
			byte[] a = sortedQueue.poll().getBytes();
			System.arraycopy(a, 0, byteArray, i, a.length);
			i += a.length;
		}
		return byteArray;
	}

	public static int getCurrLen(Queue<ByteArray> queue) {
		Queue<ByteArray> sortedQueue =  new PriorityQueue<>(queue);
		//
		int currLen = 0;		
		byte[] b = sortedQueue.poll().getBytes();
		int maxOS = ipParser.getfragOffset(b)*8;
		int minOS = ipParser.getfragOffset(b)*8;
		int i = sortedQueue.size();
		while(sortedQueue.size()>=1){
			byte[] a = sortedQueue.poll().getBytes();
			maxOS = Math.max(maxOS,ipParser.getfragOffset(a)*8);	
			minOS = Math.min(minOS,ipParser.getfragOffset(a)*8);
			i--;
			if (i == 0){
				currLen = (maxOS - minOS) + ipParser.getIpPayload(a).length;
			}
		}	
		return currLen;
	}
	
	public static byte[] getPayloadFromQueue(Queue<ByteArray> queue, int size){
		byte[] payload = new byte[size];
		Queue<ByteArray> sortedQueue =  new PriorityQueue<>(queue);		
		while(sortedQueue.size() >= 1){
			byte[] a = sortedQueue.poll().getBytes();
			int os = ipParser.getfragOffset(a)*8;
			byte[] pl = ipParser.getIpPayload(a);
			for (int i = 0; i < pl.length; i++){
				payload[i+os] = pl[i];
			}
		}
		return payload;
	}
	
	public static byte[] assemblePacket(byte[] etherHeader, byte[] header, byte[] payload, int sid, byte[] fragmentList){
		byte[] packet = new byte[etherHeader.length+header.length+payload.length+1+fragmentList.length];
		
		for (int i = 0; i < etherHeader.length; i++){
			packet[i] = etherHeader[i];
		}
		
		for (int i = 0; i < header.length; i++){
			packet[etherHeader.length+i] = header[i];
		}
		for (int i = 0; i < payload.length; i++){
			packet[etherHeader.length+header.length+i] = payload[i];
		}

		packet[etherHeader.length+header.length+payload.length] = (byte)sid;

		for (int i = 0; i < fragmentList.length; i++){
			packet[etherHeader.length+i+header.length+1+payload.length] = fragmentList[i];
		}		
		return packet;		
	}
	
	public static byte[] assemblePacket(byte[] etherPacket, int sid){
		byte[] packet = new byte[etherPacket.length + 1];
		
		for (int i = 0; i < etherPacket.length; i++){
			packet[i] = etherPacket[i];
		}
		packet[etherPacket.length] = (byte)sid;
		
		return packet;
	}
	
	public static boolean checkForGap(Queue<ByteArray> queue){
		boolean isGapped=false;
		Queue<ByteArray> sortedQueue =  new PriorityQueue<>(queue);		
		int prev = 0;
		byte[] a = sortedQueue.poll().getBytes();			
		prev = ipParser.getfragOffset(a)*8 + ipParser.getIpPayload(a).length;
		while(sortedQueue.size() >= 1){
			byte[] b = sortedQueue.poll().getBytes();
			int next = ipParser.getfragOffset(b)*8 + ipParser.getIpPayload(b).length;
			int nextOS = ipParser.getfragOffset(b)*8;
			if(prev >= nextOS){
				prev = next;
			}else{
				isGapped = true;
				return isGapped;
			}
		}
		
		return isGapped;
	}
	
	public static boolean checkForOverlap(Queue<ByteArray> queue){
		boolean isOverlapped=false;
		Queue<ByteArray> sortedQueue =  new PriorityQueue<>(queue);
		
		int prev = 0;
		byte[] a = sortedQueue.poll().getBytes();			
		prev = ipParser.getfragOffset(a)*8 + ipParser.getIpPayload(a).length;
		while(sortedQueue.size() >= 1){
			byte[] b = sortedQueue.poll().getBytes();
			int next = ipParser.getfragOffset(b)*8 + ipParser.getIpPayload(b).length;
			int nextOS = ipParser.getfragOffset(b)*8;
			if(prev > nextOS){
				isOverlapped = true;
				return isOverlapped;
			}else{
				prev = next;
			}
		}
		return isOverlapped;
	}
	
	public static byte[] copyByteArray(byte[] b, int beginInt){
		byte[] a = new byte[b.length-beginInt]; 
		int j = 0;
		for (int i = beginInt; i < b.length; i++){
			a[j] = b[i];
			j++;
		}
		return a;
	}

	public static String getString(byte[] b){
		StringBuilder sb = new StringBuilder();
        for (byte i : b){
            sb.append(String.format("%02X", i));
            sb.append(" ");
        }
        String s = sb.toString();
        return s;
	}
	
	public static String getIPAddress(String ipString){
		String ip = "";
		for(int i = 0; i < ipString.length(); i = i + 2) {
		    ip = ip + Integer.valueOf(ipString.substring(i, i+2), 16) + ".";
		}
		return ip;
	}
	public static int byteArrayToInt(byte[] b){
		ByteBuffer wrapped = ByteBuffer.wrap(b); // big-endian by default
		short value = wrapped.getShort(); // 1
		return value;
	}	
}