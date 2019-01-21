package firewall;

import java.util.*;
import java.io.*;

public class Firewall {

	private String filePath;
	private int capacity = 1000;
	private Map<String,String> ruleMap;
	private Map<String,Integer> ruleCountMap;
	private Map<Integer,LinkedList<String>> countListMap;
	private BufferedReader reader;
	private int min = -1;
	
	public Firewall(String path) 
	{
		this.filePath = path;
		ruleMap = new HashMap<String,String>();
		ruleCountMap = new HashMap<String,Integer>();
		countListMap = new HashMap<Integer,LinkedList<String>>();
		countListMap.put(1, new LinkedList<String>());

		loadCache(filePath);
		
	}
	/*
	 * This method loads cache with first 1000 rules when object is intialized
	 */
	private void loadCache(String path) 
	{
		try {
			
			reader = new BufferedReader(new FileReader(filePath));
			String line = reader.readLine();
			min = 1;
			while(capacity > ruleMap.size() && line != null) {
				
				ruleMap.put(line, line);
				ruleCountMap.put(line,1);
				countListMap.get(1).add(line);
				line = reader.readLine();
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			try {
				reader.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
	}
	/*
	 * This Method is the only public method it helps in validating the rule with the help of cache first if not validates the packet with the help of rules present 
	 * in file
	 */
	
	/**
	 * @param direction
	 * @param protocol
	 * @param port
	 * @param ip_address
	 * @return
	 */
	public boolean accept_packet(String direction,String protocol, int port,String ip_address) 
	{
		
		for(Map.Entry<String, String> entry : ruleMap.entrySet()) {
			boolean output = check_input(entry.getValue(), direction, protocol, port, ip_address);
			if(output == true) {
				
				return true;
			}
			else
			{
				continue;
			}
		}
		return accept_packet_file(direction,protocol,port,ip_address);
		
		
	}
	
	/*
	 *  This method validates the Ip Address.
	 * 
	 * */
	
	private boolean checkIp_address(String rule,String ip_address)
	{
		String[] rule_ips = rule.split("\\.");
		String[] address_ips = ip_address.split("\\.");
		if(address_ips.length != 4 || checK_IPLimits(address_ips)) 
		{
			
			return false;
		}
		if(rule_ips.length == 4)
		{
			if(Integer.parseInt(rule_ips[0]) == Integer.parseInt(address_ips[0])
				&& Integer.parseInt(rule_ips[1]) == Integer.parseInt(address_ips[1])
				&& Integer.parseInt(rule_ips[2]) == Integer.parseInt(address_ips[2])
				&& Integer.parseInt(rule_ips[3]) == Integer.parseInt(address_ips[3]))
			{
				return true;
			}
			else {
				return false;
			}
		}
		else 
		{
			String[] rule_ip_range = rule.split("-");
			String[] lower_bound = rule_ip_range[0].split("\\.");
			String[] upper_bound = rule_ip_range[1].split("\\.");
			if(check_IPinLowerRange(lower_bound[0],address_ips[0])
					|| check_IPinLowerRange(lower_bound[1],address_ips[1])
					|| check_IPinLowerRange(lower_bound[2],address_ips[2])
					|| check_IPinLowerRange(lower_bound[3],address_ips[3])){
				if(check_IPinUpperRange(upper_bound[0],address_ips[0])
						|| check_IPinUpperRange(upper_bound[1],address_ips[1])
						|| check_IPinUpperRange(upper_bound[2],address_ips[2])
						|| check_IPinUpperRange(upper_bound[3],address_ips[3]))
				{
					return  true;
				}
				else {
					return false;
				}
			}
			else {
				return false;
			}			
		}
	}
	/*
	 * This method is used to validate given packet with the help of rules present in file, file I/O operations are done in this method.
	 */
	
	private boolean accept_packet_file(String direction,String protocol, int port,String ip_address) {
		try {
			reader = new BufferedReader(new FileReader(filePath));
			String line = reader.readLine();
			while(line != null) 
			{
				boolean output = check_input(line, direction, protocol, port, ip_address);
				if(output == true) {
					return true;
				}
				else {
					line = reader.readLine();
					continue;
				}	
			}
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		finally {
			try {
				reader.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		return false;
	}
	
	/*
			All the input validations are carried out in this method. This methos internally calls checkIp_address method in order to validate the Ip_address.
	*/
	private boolean check_input(String s,String direction,String protocol, int port,String ip_address) {
		String[] rule = s.split(",");
		boolean portFlag = false;
		String[] ports = rule[2].split("-");
		if(ports.length == 2) 
		{
			
			portFlag = true;
		}
		if(!rule[0].equals(direction)) {
			return false;
		}
		else if(!rule[1].equals(protocol)) {
			return false;
		}
		else if(portFlag && !((Integer.parseInt(ports[0])<= port) && (Integer.parseInt(ports[1])>= port))){
			return false;
		}
		else if(!portFlag && Integer.parseInt(rule[2]) != port) {
			return false;
		}
		else if(checkIp_address(rule[3],ip_address)) 
		{
			if(ruleMap.containsKey(s)){
				int count = ruleCountMap.get(s);
				ruleCountMap.put(s, count +1);
				countListMap.get(count).remove(s);
				if(countListMap.get(count).size() == 0 && min == count) {
					min++;
				}
				if(!countListMap.containsKey(count+1)) {
					countListMap.put(count+1, new LinkedList<String>());
				}
				countListMap.get(count+1).add(s);
			}
			else{
				String emit = countListMap.get(min).iterator().next();
				countListMap.get(min).remove(emit);
				ruleMap.remove(emit);
				ruleCountMap.remove(emit);
				ruleMap.put(s, s);
				ruleCountMap.put(s, 1);
				min = 1;
				countListMap.get(1).add(s);
			}
			return true;
		}
		
		return false;
	}
	
	/*
	 * This Method helps to check every number in IP address is in range 0-255 
	 * */
	private boolean checK_IPLimits(String[] ip_address) 
	{
		for(String s : ip_address)
		{
			if(Integer.parseInt(s) < 0 || Integer.parseInt(s) > 255) {
				
				return true;
			}
		}
		return false;
		
	}
	
	/*
	 * This Method helps to check lower bound in IP address if a rule has a range
	 * */
	
	private boolean check_IPinLowerRange(String lower_bound, String address_ips) 
	{
		if(Integer.parseInt(lower_bound) < Integer.parseInt(address_ips)) {
			return true;
		}
		return false;
	}
	
	/*
	 * This Method helps to check upper bound in IP address if a rule has a range
	 * */
	private boolean check_IPinUpperRange(String lower_bound, String address_ips) {
		if(Integer.parseInt(lower_bound) > Integer.parseInt(address_ips)) {
			return true;
		}
		return false;
	}
}
