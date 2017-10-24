import java.io.*;
import java.util.StringTokenizer;

public class rulesParser{
	public static String[] readRules(String ruleDoc){
		FileReader fileReader = null;
		BufferedReader bufferedReader;
		int c;
		StringBuilder line;
		String[] ruleSet = null;
		try {
			File file = new File(ruleDoc);
			fileReader = new FileReader(file);
			bufferedReader = new BufferedReader(fileReader);
			line = new StringBuilder();
			while ((c = bufferedReader.read()) != -1) { 			
				line.append((char)c);				
			}
			String string = line.toString();
			ruleSet = string.split("# "); //read files into a string array
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}		
		return ruleSet;
	}
	
	public static String getAction(String rule){
		StringTokenizer st = new StringTokenizer(rule);
		return st.nextToken();
	}
	
	public static String getProt(String rule){
		StringTokenizer st = new StringTokenizer(rule);
		String prot = null;
		int count = 0;
		while (st.hasMoreTokens()){
			st.nextToken();
			count++;			
			if (count == 1){
				prot = st.nextToken();
				break;
			}
		}		
		return prot;
	}
	
	public static String getSourceIP(String rule){
		StringTokenizer st = new StringTokenizer(rule);
		String ip = null;
		int count = 0;
		while (st.hasMoreTokens()){
			st.nextToken();
			count++;			
			if (count == 2){
				ip = st.nextToken();
				break;
			}
		}		
		return ip;
	}
	
	public static String getSourcePort(String rule){
		StringTokenizer st = new StringTokenizer(rule);
		String p = null;
		int count = 0;
		while (st.hasMoreTokens()){
			st.nextToken();
			count++;			
			if (count == 3){
				p = st.nextToken();
				break;
			}
		}		
		return p;
	}
	
	public static String getDestIP(String rule){
		StringTokenizer st = new StringTokenizer(rule);
		String p = null;
		int count = 0;
		while (st.hasMoreTokens()){
			st.nextToken();
			count++;			
			if (count == 5){
				p = st.nextToken();
				break;
			}
		}		
		return p;
	}
	
	public static String getDestPort(String rule){
		StringTokenizer st = new StringTokenizer(rule);
		String p = null;
		int count = 0;
		while (st.hasMoreTokens()){
			st.nextToken();
			count++;			
			if (count == 6){
				p = st.nextToken();
				break;
			}
		}		
		return p;
	}
	
	public static String getOption(String rule){
		StringTokenizer st = new StringTokenizer(rule);
		StringBuilder p = new StringBuilder();
		String s;
		int count = 0;
		while (st.hasMoreTokens()){
			s = st.nextToken();
			count++;
			if (count >= 8){
				p.append(s);
				p.append(" ");
			}
		}
		return p.toString();
	}	
}