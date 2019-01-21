package firewall;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * @author DilipReddy
 *
 */
public class AcceptPacketTest {

	/**
	 * 
	 */
	@Test
	public void testPortNumber() {
		Firewall firewall = new Firewall("testFile.csv");
		assertTrue(firewall.accept_packet("inbound", "udp", 61000, "0.168.100.125"));
	}
	
	
	@Test
	public void testDirection() {
		Firewall firewall = new Firewall("testFile.csv");
		assertFalse(firewall.accept_packet("upbound", "tcp", 54, "192.168.2.1"));
	}
	
	@Test
	public void testProtocol() {
		Firewall firewall = new Firewall("testFile.csv");
		assertFalse(firewall.accept_packet("outbound", "mdp", 53, "192.168.2.1"));
	}
	
	@Test
	public void testIPAdress() {
		Firewall firewall = new Firewall("testFile.csv");
		assertFalse(firewall.accept_packet("outbound", "udp", 54, "300.168.100.124"));
	}
	
	@Test
	public void testCustom() {
		Firewall firewall = new Firewall("testFile.csv");
		assertFalse(firewall.accept_packet("inbound", "udp", 54, "300.168.100.124"));
	}

}
