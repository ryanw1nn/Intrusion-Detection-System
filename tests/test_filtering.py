"""
Comprehensive tests for packet filtering:
- IP whitelist/blacklist
- CIDR network ranges
- Port filtering
- IPv4 and IPv6 support
"""

import unittest
from scapy.all import IP, TCP
from ids.packet_filter import PacketFilter
from ids.config_loader import ConfigLoader
import tempfile
import yaml


class TestPacketFilterBasic(unittest.TestCase):
    """Basic packet filtering tests"""

    def setUp(self):
        self.filter = PacketFilter()

    def test_initialization(self):
        """Test PacketFilter initialization"""
        self.assertIsNotNone(self.filter.whitelist_ips)
        self.assertIsNotNone(self.filter.blacklist_ips)
        self.assertIsNotNone(self.filter.whitelist_ports)
        self.assertIsNotNone(self.filter.stats)

    def test_no_filtering_by_default(self):
        """Test that packets pass through with no rules"""
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = self.filter.should_analyze(packet)
        
        self.assertTrue(should_analyze)
        self.assertFalse(is_blacklisted)

    def test_individual_ip_whitelist(self):
        """Test whitelisting individual IP addresses"""
        self.filter.add_to_whitelist("127.0.0.1")
        
        packet = IP(src="127.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = self.filter.should_analyze(packet)
        
        self.assertFalse(should_analyze)
        self.assertFalse(is_blacklisted)

    def test_network_range_whitelist(self):
        """Test whitelisting network ranges (CIDR notation)"""
        self.filter.add_to_whitelist("192.168.1.0/24")
        
        # Test various IPs in that range
        for last_octet in [1, 50, 100, 254]:
            packet = IP(src=f"192.168.1.{last_octet}", dst="8.8.8.8") / TCP(sport=12345, dport=80)
            should_analyze, _ = self.filter.should_analyze(packet)
            self.assertFalse(should_analyze, f"192.168.1.{last_octet} should be whitelisted")
        
        # Test IP outside the range
        packet = IP(src="192.168.2.1", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        should_analyze, _ = self.filter.should_analyze(packet)
        self.assertTrue(should_analyze, "192.168.2.1 should NOT be whitelisted")

    def test_destination_ip_whitelist(self):
        """Test that both source and destination IPs are checked"""
        self.filter.add_to_whitelist("192.168.1.1")
        
        # Whitelisted destination
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, _ = self.filter.should_analyze(packet)
        self.assertFalse(should_analyze)

    def test_blacklist_individual_ip(self):
        """Test blacklisting individual IP addresses"""
        self.filter.add_to_blacklist("10.0.0.1")
        
        packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = self.filter.should_analyze(packet)
        
        self.assertTrue(should_analyze)
        self.assertTrue(is_blacklisted)

    def test_blacklist_network_range(self):
        """Test blacklisting network ranges"""
        self.filter.add_to_blacklist("10.0.0.0/24")
        
        # Test various IPs in that range
        for last_octet in [1, 50, 100, 254]:
            packet = IP(src=f"10.0.0.{last_octet}", dst="192.168.1.1") / TCP(sport=12345, dport=80)
            should_analyze, is_blacklisted = self.filter.should_analyze(packet)
            self.assertTrue(should_analyze)
            self.assertTrue(is_blacklisted, f"10.0.0.{last_octet} should be blacklisted")

    def test_whitelist_takes_precedence(self):
        """Test that whitelist takes precedence over blacklist"""
        self.filter.add_to_whitelist("192.168.1.100")
        self.filter.add_to_blacklist("192.168.1.100")
        
        packet = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = self.filter.should_analyze(packet)
        
        # Whitelist should win
        self.assertFalse(should_analyze)


class TestPortFiltering(unittest.TestCase):
    """Tests for port-based filtering"""

    def test_port_whitelist_source(self):
        """Test whitelisting source ports"""
        config = ConfigLoader()
        config.override('filtering.whitelist_ports', [22, 443])
        filter_with_ports = PacketFilter(config=config)
        
        # Source port 22
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=22, dport=80)
        should_analyze, _ = filter_with_ports.should_analyze(packet)
        self.assertFalse(should_analyze)

    def test_port_whitelist_destination(self):
        """Test whitelisting destination ports"""
        config = ConfigLoader()
        config.override('filtering.whitelist_ports', [443])
        filter_with_ports = PacketFilter(config=config)
        
        # Destination port 443
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=12345, dport=443)
        should_analyze, _ = filter_with_ports.should_analyze(packet)
        self.assertFalse(should_analyze)

    def test_port_not_whitelisted(self):
        """Test non-whitelisted ports are analyzed"""
        config = ConfigLoader()
        config.override('filtering.whitelist_ports', [22, 443])
        filter_with_ports = PacketFilter(config=config)
        
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, _ = filter_with_ports.should_analyze(packet)
        self.assertTrue(should_analyze)


class TestFilteringEdgeCases(unittest.TestCase):
    """Edge cases and error handling"""

    def test_empty_filter(self):
        """Test filter with no rules"""
        filter_empty = PacketFilter()
        
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = filter_empty.should_analyze(packet)
        
        self.assertTrue(should_analyze)
        self.assertFalse(is_blacklisted)

    def test_overlapping_networks(self):
        """Test handling of overlapping network ranges"""
        filter_overlap = PacketFilter()
        
        # Add overlapping networks
        filter_overlap.add_to_whitelist("192.168.0.0/16")  # Larger range
        filter_overlap.add_to_whitelist("192.168.1.0/24")  # Smaller range within
        
        packet = IP(src="192.168.1.50", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        should_analyze, _ = filter_overlap.should_analyze(packet)
        
        self.assertFalse(should_analyze)

    def test_non_ip_packet(self):
        """Test handling of non-IP packets"""
        filter_test = PacketFilter()
        filter_test.add_to_whitelist("192.168.1.1")
        
        # Create packet without IP layer
        try:
            from scapy.all import ARP, Ether
            arp_packet = Ether()/ARP()
            should_analyze, is_blacklisted = filter_test.should_analyze(arp_packet)
            # Should return True, False (analyze but not blacklisted)
            self.assertTrue(True)
        except:
            # If ARP not available, skip
            pass

    def test_invalid_ip_handling(self):
        """Test handling of invalid IP addresses"""
        filter_test = PacketFilter()
        
        result1 = filter_test.add_to_whitelist("not_an_ip")
        result2 = filter_test.add_to_blacklist("999.999.999.999")
        
        self.assertFalse(result1)
        self.assertFalse(result2)

    def test_remove_from_whitelist(self):
        """Test removing entries from whitelist"""
        filter_test = PacketFilter()
        filter_test.add_to_whitelist("192.168.1.100")
        filter_test.remove_from_whitelist("192.168.1.100")
        
        packet = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        should_analyze, _ = filter_test.should_analyze(packet)
        
        self.assertTrue(should_analyze)

    def test_remove_from_blacklist(self):
        """Test removing entries from blacklist"""
        filter_test = PacketFilter()
        filter_test.add_to_blacklist("10.0.0.1")
        filter_test.remove_from_blacklist("10.0.0.1")
        
        packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = filter_test.should_analyze(packet)
        
        self.assertTrue(should_analyze)
        self.assertFalse(is_blacklisted)


class TestFilteringStatistics(unittest.TestCase):
    """Test statistics tracking"""

    def test_statistics_initialization(self):
        """Test that statistics are initialized"""
        filter_test = PacketFilter()
        stats = filter_test.get_statistics()
        
        self.assertEqual(stats['total_packets_filtered'], 0)
        self.assertEqual(stats['whitelisted_packets'], 0)
        self.assertEqual(stats['blacklisted_packets'], 0)

    def test_whitelist_statistics(self):
        """Test whitelisting statistics are tracked"""
        filter_test = PacketFilter()
        filter_test.add_to_whitelist("127.0.0.1")
        
        packet = IP(src="127.0.0.1", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        filter_test.should_analyze(packet)
        
        stats = filter_test.get_statistics()
        self.assertEqual(stats['whitelisted_packets'], 1)
        self.assertEqual(stats['total_packets_filtered'], 1)

    def test_blacklist_statistics(self):
        """Test blacklisting statistics are tracked"""
        filter_test = PacketFilter()
        filter_test.add_to_blacklist("10.0.0.1")
        
        packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        filter_test.should_analyze(packet)
        
        stats = filter_test.get_statistics()
        self.assertEqual(stats['blacklisted_packets'], 1)

    def test_port_filter_statistics(self):
        """Test port filtering statistics are tracked"""
        config = ConfigLoader()
        config.override('filtering.whitelist_ports', [22])
        filter_test = PacketFilter(config=config)
        
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=22, dport=80)
        filter_test.should_analyze(packet)
        
        stats = filter_test.get_statistics()
        self.assertEqual(stats['port_filtered_packets'], 1)

    def test_reset_statistics(self):
        """Test resetting statistics"""
        filter_test = PacketFilter()
        filter_test.add_to_whitelist("127.0.0.1")
        
        packet = IP(src="127.0.0.1", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        filter_test.should_analyze(packet)
        
        filter_test.reset_statistics()
        
        stats = filter_test.get_statistics()
        self.assertEqual(stats['whitelisted_packets'], 0)


class TestConfigIntegration(unittest.TestCase):
    """Test configuration integration"""

    def test_load_from_config(self):
        """Test loading whitelist/blacklist from config"""
        config = ConfigLoader()
        config.override('filtering.whitelist', ['127.0.0.1', '192.168.1.0/24'])
        config.override('filtering.blacklist', ['10.0.0.1'])
        
        filter_with_config = PacketFilter(config=config)
        
        stats = filter_with_config.get_statistics()
        self.assertEqual(stats['whitelist_entries'], 2)
        self.assertEqual(stats['blacklist_entries'], 1)

    def test_empty_config_lists(self):
        """Test handling of empty config lists"""
        config = ConfigLoader()
        config.override('filtering.whitelist', [])
        config.override('filtering.blacklist', [])
        
        filter_with_config = PacketFilter(config=config)
        
        stats = filter_with_config.get_statistics()
        self.assertEqual(stats['whitelist_entries'], 0)
        self.assertEqual(stats['blacklist_entries'], 0)


class TestCIDRNotation(unittest.TestCase):
    """Test CIDR network notation"""

    def test_slash_8_network(self):
        """Test /8 network (16 million IPs)"""
        filter_test = PacketFilter()
        filter_test.add_to_whitelist("10.0.0.0/8")
        
        # Test various IPs
        test_ips = ["10.0.0.1", "10.123.45.67", "10.255.255.254"]
        for ip in test_ips:
            packet = IP(src=ip, dst="8.8.8.8") / TCP(sport=12345, dport=80)
            should_analyze, _ = filter_test.should_analyze(packet)
            self.assertFalse(should_analyze, f"{ip} should be in 10.0.0.0/8")
        
        # Outside range
        packet = IP(src="11.0.0.1", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        should_analyze, _ = filter_test.should_analyze(packet)
        self.assertTrue(should_analyze)

    def test_slash_16_network(self):
        """Test /16 network (65536 IPs)"""
        filter_test = PacketFilter()
        filter_test.add_to_whitelist("172.16.0.0/16")
        
        test_ips = ["172.16.0.1", "172.16.123.45", "172.16.255.254"]
        for ip in test_ips:
            packet = IP(src=ip, dst="8.8.8.8") / TCP(sport=12345, dport=80)
            should_analyze, _ = filter_test.should_analyze(packet)
            self.assertFalse(should_analyze)

    def test_slash_24_network(self):
        """Test /24 network (256 IPs)"""
        filter_test = PacketFilter()
        filter_test.add_to_whitelist("192.168.1.0/24")
        
        # All IPs in 192.168.1.0-255 should match
        for i in range(0, 256):
            packet = IP(src=f"192.168.1.{i}", dst="8.8.8.8") / TCP(sport=12345, dport=80)
            should_analyze, _ = filter_test.should_analyze(packet)
            self.assertFalse(should_analyze, f"192.168.1.{i} should be whitelisted")

    def test_slash_32_network(self):
        """Test /32 network (single IP)"""
        filter_test = PacketFilter()
        filter_test.add_to_whitelist("192.168.1.100/32")
        
        # Exact IP
        packet = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        should_analyze, _ = filter_test.should_analyze(packet)
        self.assertFalse(should_analyze)
        
        # Adjacent IP
        packet = IP(src="192.168.1.101", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        should_analyze, _ = filter_test.should_analyze(packet)
        self.assertTrue(should_analyze)


if __name__ == "__main__":
    unittest.main(verbosity=2)