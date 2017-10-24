public class calculateChecksum{
	public static int getChecksum(byte[] buf) {
		int length = buf.length;
		int i = 0;		
		int sum = 0;
		int data;
		
		while (length > 1) {
			data = (((buf[i] << 8) & 0xFF00) | ((buf[i + 1]) & 0xFF));
			sum += data;
			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}
			i += 2;
			length -= 2;
		}
		
		if (length > 0) {
			sum += (buf[i] << 8 & 0xFF00);
			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}
		}
		
		sum = ~sum;
		sum = sum & 0xFFFF;
		
		return sum;
	}
}