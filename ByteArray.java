public class ByteArray {
	
	private byte[] d;
	
	public ByteArray(byte[] y){
	    this.d = y;
	}
	
	public int getD(){		
	    return ipParser.getfragOffset(d);
	}
	
	public String toString() {
	    return ""+d;
	}
	
	public byte[] getBytes(){
		byte[] z = d;
		return z;
	}
	
}