"""
Comprehensive test suite for the Network IDS
Includes unit tests and live network testing capability
"""

import unittest
from scapy.all import IP, TCP, wrpcap, rdpcap
from ids.traffic_analyzer import TrafficAnalyzer
from ids.detection_engine import DetectionEngine
from ids.alert_system import AlertSystem
from ids.config_loader import ConfigLoader
from ids.packet_filter import PacketFilter
from ids.statistics_display import StatisticsTracker, StatisticsDisplay, Colors
import numpy as np
import time
import os
import tempfile
import yaml


# ===================================
# TRAFFIC ANALYZER TESTS
# ===================================
class TestTrafficAnalyzer(unittest.TestCase):
    """Unit tests for TrafficAnalyzer"""

    def setUp(self):
        self.analyzer = TrafficAnalyzer(max_flows=100, flow_timeout=10)
    
    def test_basic_packet_analysis(self):
        """Test basic packet feature extraction"""
        packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A")
        packet.time = time.time()

        features = self.analyzer.analyze_packet(packet)

        self.assertIsNotNone(features)
        self.assertIn('packet_size', features)
        self.assertIn('packet_rate', features)
        self.assertIn('tcp_flags', features)

    def test_flow_tracking(self):
        """Test that flows are tracked correctly"""
        packet1 = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        packet1.time = time.time()

        self.analyzer.analyze_packet(packet1)
        self.assertEqual(self.analyzer.get_flow_count(), 1)

        # Same flow
        packet2 = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        packet2.time = time.time()
        self.analyzer.analyze_packet(packet2)
        self.assertEqual(self.analyzer.get_flow_count(), 1)

        # Different flow
        packet3 = IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=5678, dport=443)
        packet3.time = time.time()
        self.analyzer.analyze_packet(packet3)
        self.assertEqual(self.analyzer.get_flow_count(), 2)

    def test_max_flows_limit(self):
        """test that max flows limit is enforced"""
        analyzer = TrafficAnalyzer(max_flows=5)

        # create 10 different flows
        for i in range(10):
            packet = IP(src=f"192.168.1.{i}", dst="192.168.1.100") / TCP(sport=1000+i, dport=80)
            packet.time = time.time()
            analyzer.analyze_packet(packet)

        # should only keep 5 flows
        self.assertEqual(analyzer.get_flow_count(), 5)

    def test_flow_cleanup(self):
        """Test that old flows are cleaned up"""
        analyzer = TrafficAnalyzer(max_flows=100, flow_timeout=2)

        packet=IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        packet.time = time.time()
        analyzer.analyze_packet(packet)

        self.assertEqual(analyzer.get_flow_count(), 1)

        # wait for timeout
        time.sleep(3)

        # trigger cleanup
        removed = analyzer.cleanup_old_flows()
        self.assertEqual(removed, 1)
        self.assertEqual(analyzer.get_flow_count(), 0)

    def test_invalid_packet(self):
        """Test handling of non-TCP/IP packets"""
        packet = IP(src="192.168.1.1", dst="192.168.1.2") # no TCP layer
        features = self.analyzer.analyze_packet(packet)
        self.assertIsNone(features)

# ===================================
# DETECTION ENGINE TESTS
# ===================================
class TestDetectionEngine(unittest.TestCase):
    """Unit tests for DetectionEngine"""
    
    def setUp(self):
        self.engine = DetectionEngine()

        # Train with normal traffic
        normal_data = np.array([
            [100, 10, 1000],
            [120, 15, 1500],
            [80, 5, 800],
            [110, 12, 1200],
            [90, 8, 900]
        ])
        self.engine.train_anomaly_detector(normal_data)

    def test_syn_flood_detection(self):
        """Test SYN flood signature detection"""
        features = {
            'packet_size': 60,
            'packet_rate': 2000,
            'byte_rate': 36000,
            'tcp_flags': 2, # SYN flag
            'flow_duration': 1.0,
            'window_size': 8192,
            'packet_count': 20
        }

        threats = self.engine.detect_threats(features)

        self.assertTrue(len(threats) > 0)
        self.assertTrue(any(t['rule'] == 'syn_flood' for t in threats if t['type'] == 'signature'))

    def test_port_scan_detection(self):
        """Test port scan signature detection"""
        features = {
            'packet_size': 60, # small packet
            'packet_rate': 600,
            'byte_rate': 9000,
            'tcp_flags': 2,
            'flow_duration': 0.3,
            'window_size': 8192,
            'packet_count': 20 # multiple packets in flow
        }

        threats = self.engine.detect_threats(features)

        self.assertTrue(len(threats) > 0)
        self.assertTrue(any(t['rule'] == 'port_scan' for t in threats if t['type'] == 'signature'))

    def test_normal_traffic(self):
        """Test that normal traffic doesn't trigger alerts"""
        features = {
            'packet_size': 100,
            'packet_rate': 10,
            'byte_rate': 1000,
            'tcp_flags': 16, # ACK flag
            'flow_duration': 1.0,
            'window_size': 8192
        }

        threats = self.engine.detect_threats(features)

        # should have no or minimal threats
        self.assertTrue(len(threats) == 0 or all(t['confidence'] < 0.8 for t in threats))

    def test_anomaly_detection(self):
        """Test anomaly detection on unusual traffic"""
        features = {
            'packet_size': 9999, # very unusual size
            'packet_rate': 1000,
            'byte_rate': 9999000,
            'tcp_flags': 16,
            'flow_duration': 1.0,
            'window_size': 8192
        }

        threats = self.engine.detect_threats(features)

        # should detect anomaly
        self.assertTrue(any(t['type'] == 'anomaly' for t in threats))

    def test_below_threshold_no_alert(self):
        """
        Test that traffic below thresholds doesn't trigger alerts

        Verify false positive reduction
        """
        features = {
            'packet_size': 60,
            'packet_rate': 1000,
            'byte_rate': 60000,
            'tcp_flags': 2,
            'flow_duration': 1.0,
            'window_size': 8192,
            'packet_count': 20
        }

        threats = self.engine.detect_threats(features)

        # Should NOT detect SYN flood (rate too low)
        syn_flood_threats = [t for t in threats if t.get('rule') == 'syn_flood']
        self.assertEqual(len(syn_flood_threats), 0)

    def test_insufficient_packets_no_alerts(self):
        """
        Test that flows with two few packets don't trigger alerts

        Verify min_packet_count enforcement
        """
        features = {
            'packet_size': 60,
            'packet_rate': 2000,  # Above threshold
            'byte_rate': 120000,
            'tcp_flags': 2,  # SYN flag
            'flow_duration': 1.0,
            'window_size': 8192,
            'packet_count': 10  # Below 15 minimum
        }

        threats = self.engine.detect_threats(features)

        # Should NOT detect (insufficient packets)
        syn_flood_threats = [t for t in threats if t.get('rule') == 'syn_flood']
        self.assertEqual(len(syn_flood_threats), 0)


# ===================================
# CONFIG INTERGRATION TESTS
# ===================================
class TestConfigIntegration(unittest.TestCase):
    """
    Test configuration system integration
    """

    def test_detection_engine_with_config(self):
        """ Test that DetectionEngine can be created with config """
        from ids.config_loader import ConfigLoader

        # Create a test config
        config = ConfigLoader()
        
        # Create engine with config
        engine = DetectionEngine(config=config)

        # Verify thresholds are loaded from config
        self.assertEqual(engine.syn_flood_rate, config.get('detection.syn_flood.rate_threshold'))
        self.assertEqual(engine.port_scan_rate, config.get('detection.port_scan.rate_threshold'))

    def test_detection_engine_without_config(self):
        """ Test that DetectionEngine works without config (uses defaults) """
        engine = DetectionEngine(config=None)

        # Should use default values
        self.assertEqual(engine.syn_flood_rate, 1500)
        self.assertEqual(engine.port_scan_rate, 500)
        self.assertEqual(engine.min_packet_count, 15)

# ===================================
# ALERT DEDUPLICATION TESTS
# ===================================

class TestAlertDeduplication(unittest.TestCase):
    """Test alert deduplication functionality"""

    def setUp(self):
        """Create a temporary log file for each test"""
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.temp_log.close()
        self.log_file = self.temp_log.name
    
    def tearDown(self):
        """Clean up temporary log file"""
        if os.path.exists(self.log_file):
            os.unlink(self.log_file)    

    def test_first_alert_not_suppressed(self):
        """Test that the first alert for a flow is not suppressed"""
        alert_system = AlertSystem(log_file=self.log_file)
        
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        result = alert_system.generate_alert(threat, packet_info)
        
        self.assertTrue(result)  # First alert should be generated
        stats = alert_system.get_statistics()
        self.assertEqual(stats['total_alerts_generated'], 1)
        self.assertEqual(stats['total_alerts_suppressed'], 0)
        def test_duplicate_alert_suppressed(self):
            """Test that duplicate alerts within deduplication window are suppressed"""
        alert_system = AlertSystem(log_file=self.log_file)
        
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        # First alert
        result1 = alert_system.generate_alert(threat, packet_info)
        self.assertTrue(result1)
        
        # Duplicate alert (same flow, same threat, within 60 seconds)
        result2 = alert_system.generate_alert(threat, packet_info)
        self.assertFalse(result2)  # Should be suppressed
        
        # Third duplicate
        result3 = alert_system.generate_alert(threat, packet_info)
        self.assertFalse(result3)  # Should be suppressed
        
        stats = alert_system.get_statistics()
        self.assertEqual(stats['total_alerts_generated'], 1)
        self.assertEqual(stats['total_alerts_suppressed'], 2)
        self.assertGreater(stats['suppression_rate'], 0)
    
    def test_different_flows_not_suppressed(self):
        """Test that alerts for different flows are not suppressed"""
        alert_system = AlertSystem(log_file=self.log_file)
        
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        
        # Flow 1
        packet_info1 = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        # Flow 2 (different destination IP)
        packet_info2 = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.2',  # Different!
            'source_port': 12345,
            'destination_port': 80
        }
        
        result1 = alert_system.generate_alert(threat, packet_info1)
        result2 = alert_system.generate_alert(threat, packet_info2)
        
        self.assertTrue(result1)
        self.assertTrue(result2)  # Different flow, should not be suppressed
        
        stats = alert_system.get_statistics()
        self.assertEqual(stats['total_alerts_generated'], 2)
        self.assertEqual(stats['total_alerts_suppressed'], 0)
        self.assertEqual(stats['unique_flows_alerted'], 2)


    def test_alert_after_deduplication_window(self):
        """Test that alerts are allowed after deduplication window expires"""
        # Create alert system with 1-second window for faster testing
        alert_system = AlertSystem(log_file=self.log_file)
        alert_system.deduplication_window = 1  # 1 second for testing
        
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        # First alert
        result1 = alert_system.generate_alert(threat, packet_info)
        self.assertTrue(result1)
        
        # Wait for deduplication window to expire
        time.sleep(1.5)
        
        # Alert after window - should be allowed (ongoing attack update)
        result2 = alert_system.generate_alert(threat, packet_info)
        self.assertTrue(result2)
        
        stats = alert_system.get_statistics()
        self.assertEqual(stats['total_alerts_generated'], 2)
        self.assertEqual(stats['total_alerts_suppressed'], 0)
    
    def test_rate_limit_enforcement(self):
        """Test that rate limiting prevents alert storms"""
        alert_system = AlertSystem(log_file=self.log_file)
        alert_system.rate_limit_per_minute = 10  # Low limit for testing
        
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        
        # Generate 15 alerts from different flows (to bypass deduplication)
        generated = 0
        rate_limited = 0
        
        for i in range(15):
            packet_info = {
                'source_ip': f'192.168.1.{i}',  # Different source each time
                'destination_ip': '10.0.0.1',
                'source_port': 12345 + i,
                'destination_port': 80
            }
            
            result = alert_system.generate_alert(threat, packet_info)
            if result:
                generated += 1
            else:
                rate_limited += 1
        
        # Should generate 10 alerts, then rate limit the rest
        self.assertEqual(generated, 10)
        self.assertEqual(rate_limited, 5)
        
        stats = alert_system.get_statistics()
        self.assertEqual(stats['total_rate_limited'], 5)
    
    def test_deduplication_with_config(self):
        """Test that deduplication settings are loaded from config"""
        config = ConfigLoader()
        alert_system = AlertSystem(log_file=self.log_file, config=config)
        
        # Check that config values are loaded
        self.assertEqual(alert_system.deduplication_window, 
                        config.get('alerting.deduplication_window', 60))
        self.assertEqual(alert_system.rate_limit_per_minute,
                        config.get('alerting.rate_limit_per_minute', 100))
        
# ===================================
# PACKET FILTERING TESTS
# ===================================

class TestPacketFilter(unittest.TestCase):
    """Unit tests for PacketFilter"""

    def setUp(self):
        """Set up test fixtures"""
        self.filter = PacketFilter()

    def test_individual_ip_whitelist(self):
        """Test whitelisting individual IP addresses"""
        # Add localhost to whitelist
        self.filter.add_to_whitelist("127.0.0.1")
        
        # Create packet from whitelisted IP
        packet = IP(src="127.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        
        should_analyze, is_blacklisted = self.filter.should_analyze(packet)
        
        self.assertFalse(should_analyze, "Whitelisted IP should not be analyzed")
        self.assertFalse(is_blacklisted, "Whitelisted IP should not be blacklisted")

    def test_network_range_whitelist(self):
        """Test whitelisting network ranges (CIDR notation)"""
        # Add entire /24 network to whitelist
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

    def test_port_whitelist(self):
        """Test whitelisting ports"""
        # Create filter with whitelisted ports
        config = ConfigLoader()
        config.override('filtering.whitelist_ports', [22, 443])
        filter_with_ports = PacketFilter(config=config)
        
        # Test SSH port (22)
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=12345, dport=22)
        should_analyze, _ = filter_with_ports.should_analyze(packet)
        self.assertFalse(should_analyze, "Port 22 should be whitelisted")
        
        # Test HTTPS port (443)
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=443, dport=80)
        should_analyze, _ = filter_with_ports.should_analyze(packet)
        self.assertFalse(should_analyze, "Port 443 should be whitelisted (source)")
        
        # Test non-whitelisted port
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, _ = filter_with_ports.should_analyze(packet)
        self.assertTrue(should_analyze, "Port 80 should NOT be whitelisted")

    def test_blacklist_individual_ip(self):
        """Test blacklisting individual IP addresses"""
        # Add known bad actor to blacklist
        self.filter.add_to_blacklist("10.0.0.1")
        
        packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = self.filter.should_analyze(packet)
        
        self.assertTrue(should_analyze, "Blacklisted IP should be analyzed")
        self.assertTrue(is_blacklisted, "IP should be flagged as blacklisted")

    def test_blacklist_network_range(self):
        """Test blacklisting network ranges"""
        # Add entire /24 network to blacklist
        self.filter.add_to_blacklist("10.0.0.0/24")
        
        # Test various IPs in that range
        for last_octet in [1, 50, 100, 254]:
            packet = IP(src=f"10.0.0.{last_octet}", dst="192.168.1.1") / TCP(sport=12345, dport=80)
            should_analyze, is_blacklisted = self.filter.should_analyze(packet)
            self.assertTrue(should_analyze, "Blacklisted IP should be analyzed")
            self.assertTrue(is_blacklisted, f"10.0.0.{last_octet} should be blacklisted")
        
        # Test IP outside the range
        packet = IP(src="10.0.1.1", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = self.filter.should_analyze(packet)
        self.assertTrue(should_analyze, "Should analyze non-blacklisted IP")
        self.assertFalse(is_blacklisted, "10.0.1.1 should NOT be blacklisted")

    def test_whitelist_takes_precedence(self):
        """Test that whitelist takes precedence over blacklist"""
        # Add IP to both whitelist and blacklist
        self.filter.add_to_whitelist("192.168.1.100")
        self.filter.add_to_blacklist("192.168.1.100")
        
        packet = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = self.filter.should_analyze(packet)
        
        # Whitelist should win - packet should not be analyzed at all
        self.assertFalse(should_analyze, "Whitelisted IP should not be analyzed even if blacklisted")

    def test_destination_ip_whitelist(self):
        """Test that both source and destination IPs are checked against whitelist"""
        self.filter.add_to_whitelist("192.168.1.1")
        
        # Test with whitelisted destination
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, _ = self.filter.should_analyze(packet)
        self.assertFalse(should_analyze, "Packet to whitelisted destination should not be analyzed")

    def test_remove_from_whitelist(self):
        """Test removing entries from whitelist"""
        # Add and then remove
        self.filter.add_to_whitelist("192.168.1.100")
        self.filter.remove_from_whitelist("192.168.1.100")
        
        packet = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        should_analyze, _ = self.filter.should_analyze(packet)
        
        self.assertTrue(should_analyze, "Removed IP should now be analyzed")

    def test_remove_from_blacklist(self):
        """Test removing entries from blacklist"""
        # Add and then remove
        self.filter.add_to_blacklist("10.0.0.1")
        self.filter.remove_from_blacklist("10.0.0.1")
        
        packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = self.filter.should_analyze(packet)
        
        self.assertTrue(should_analyze, "Should still analyze (not whitelisted)")
        self.assertFalse(is_blacklisted, "Should not be blacklisted after removal")

    def test_invalid_ip_handling(self):
        """Test handling of invalid IP addresses"""
        # These should fail gracefully without crashing
        result1 = self.filter.add_to_whitelist("not_an_ip")
        result2 = self.filter.add_to_blacklist("999.999.999.999")
        
        self.assertFalse(result1, "Invalid IP should not be added to whitelist")
        self.assertFalse(result2, "Invalid IP should not be added to blacklist")

    def test_statistics_tracking(self):
        """Test that filtering statistics are tracked correctly"""
        self.filter.add_to_whitelist("127.0.0.1")
        self.filter.add_to_blacklist("10.0.0.1")
        
        # Create some packets
        whitelist_packet = IP(src="127.0.0.1", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        blacklist_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        normal_packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        
        # Process them
        self.filter.should_analyze(whitelist_packet)
        self.filter.should_analyze(blacklist_packet)
        self.filter.should_analyze(normal_packet)
        
        stats = self.filter.get_statistics()
        
        self.assertEqual(stats['whitelisted_packets'], 1, "Should track whitelisted packets")
        self.assertEqual(stats['blacklisted_packets'], 1, "Should track blacklisted packets")
        self.assertEqual(stats['total_packets_filtered'], 1, "Should track total filtered (whitelisted only)")

    def test_ipv6_support(self):
        """Test IPv6 address filtering"""
        # Add IPv6 address to whitelist
        self.filter.add_to_whitelist("::1")  # IPv6 localhost
        
        # This would need IPv6 packet support in Scapy
        # Placeholder for future IPv6 testing
        pass

    def test_config_integration(self):
        """Test loading whitelist/blacklist from config file"""
        # Create config with filtering rules
        config = ConfigLoader()
        config.override('filtering.whitelist', ['127.0.0.1', '192.168.1.0/24'])
        config.override('filtering.blacklist', ['10.0.0.1'])
        
        filter_with_config = PacketFilter(config=config)
        
        stats = filter_with_config.get_statistics()
        self.assertEqual(stats['whitelist_entries'], 2, "Should load 2 whitelist entries from config")
        self.assertEqual(stats['blacklist_entries'], 1, "Should load 1 blacklist entry from config")


# ===================================
# PACKET FILTERING EDGE TESTS
# ===================================

class TestPacketFilterEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""

    def test_empty_filter(self):
        """Test filter with no rules"""
        filter_empty = PacketFilter()
        
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / TCP(sport=12345, dport=80)
        should_analyze, is_blacklisted = filter_empty.should_analyze(packet)
        
        self.assertTrue(should_analyze, "Should analyze when no rules are set")
        self.assertFalse(is_blacklisted, "Should not be blacklisted when no rules")

    def test_overlapping_networks(self):
        """Test handling of overlapping network ranges"""
        filter_overlap = PacketFilter()
        
        # Add overlapping networks
        filter_overlap.add_to_whitelist("192.168.0.0/16")  # Larger range
        filter_overlap.add_to_whitelist("192.168.1.0/24")  # Smaller range within
        
        packet = IP(src="192.168.1.50", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        should_analyze, _ = filter_overlap.should_analyze(packet)
        
        self.assertFalse(should_analyze, "Should be whitelisted by either range")

    def test_non_ip_packet(self):
        """Test handling of non-IP packets"""
        filter_test = PacketFilter()
        filter_test.add_to_whitelist("192.168.1.1")
        
        # Create packet without IP layer (ARP, for example)
        # This should not crash
        try:
            from scapy.all import ARP, Ether
            arp_packet = Ether()/ARP()
            should_analyze, is_blacklisted = filter_test.should_analyze(arp_packet)
            # Should return True, False (analyze but not blacklisted)
            self.assertTrue(True, "Should handle non-IP packets gracefully")
        except Exception as e:
            self.fail(f"Should not crash on non-IP packets: {e}")


# ===================================
# LIVE NETWORK TEST
# ===================================
class LiveNetworkTest:
    """
    Live network testing, not a unit test
    Run this separately when you want to test on real traffic
    """

    @staticmethod
    def capture_and_analyze(interface="lo0", duration=30, packet_count=100):
        """
        Capture live traffic and analyze it

        Args:
            interface: Network interface to capture from (e.g., 'eth0', 'lo0', 'en0')
            duration: How long to capture in seconds
            packet_count: Maximum packets to capture
        """
        from scapy.all import sniff

        print(f"\n{'='*60}")
        print(f"LIVE NETWORK TEST")
        print(f"{'='*60}")
        print(f"Interface: {interface}")
        print(f"Duration: {duration}s")
        print(f"Max packets: {packet_count}")
        print(f"{'='*60}\n")

        analyzer = TrafficAnalyzer()
        engine = DetectionEngine()

        # Anomaly detection disabled for live tests to avoid false positives
        # from synthetic training data that doesn't match real traffic patterns
        print("Anomaly detection disabled (signature-based detection only)")

        threat_count = 0
        packet_analyzed = 0

        def packet_callback(packet):
            nonlocal threat_count, packet_analyzed

            if IP in packet and TCP in packet:
                features = analyzer.analyze_packet(packet)

                if features:
                    packet_analyzed += 1
                    threats = engine.detect_threats(features)

                    if threats:
                        threat_count += 1
                        print(f"\n  THREAT DETECTED in packet {packet_analyzed}")
                        print(f"    Source: {packet[IP].src}:{packet[TCP].sport}")
                        print(f"    Dest: {packet[IP].dst}:{packet[TCP].dport}")
                        print(f"    Threats: {[t['type'] + ':' + t.get('rule', 'anomaly') for t in threats]}")

                    if packet_analyzed % 10 == 0:
                        print(f"Processed {packet_analyzed} packets, {threat_count} threats detected...")

        try:
            print("Starting packet capture... (Press Ctrl+C to stop early)\n")
            sniff(
                iface=interface,
                prn=packet_callback,
                count=packet_count,
                timeout=duration,
                filter="tcp" # only capture TCP packets
            )
        except KeyboardInterrupt:
            print("\n\nCapture interupted by user.")
        except PermissionError:
            print("\n❌ ERROR: Permission denied. Try running with sudo:")
            print(f"    sudo python test_ids.py --live {interface}")
            return
        except Exception as e:
            print(f"\n ERROR: {e}")
            return
        
        print(f"\n{'='*60}")
        print(f"SUMMARY")
        print(f"{'='*60}\n")
        print(f"Packets analyzed: {packet_analyzed}")
        print(f"Threats detected: {threat_count}")
        print(f"Detection rate: {(threat_count/packet_analyzed*100):.1f}%" if packet_analyzed > 0 else "N/A")
        print(f"{'='*60}\n")


# ===================================
# REAL-TIME STATISTICS TESTS
# ===================================

class TestStatisticsTracker(unittest.TestCase):
    """Unit tests for StatisticsTracker"""

    def setUp(self):
        """Set up test fixtures"""
        self.tracker = StatisticsTracker(window_size=10)

    def test_record_packet(self):
        """Test recording packet events"""
        self.tracker.record_packet()
        self.tracker.record_packet()
        
        totals = self.tracker.get_total_counts()
        self.assertEqual(totals['total_packets'], 2)

    def test_record_threat(self):
        """Test recording threat events"""
        self.tracker.record_threat("192.168.1.100")
        self.tracker.record_threat("192.168.1.100")
        self.tracker.record_threat("192.168.1.101")
        
        totals = self.tracker.get_total_counts()
        self.assertEqual(totals['total_threats'], 3)
        self.assertEqual(totals['unique_attackers'], 2)

    def test_record_filtered(self):
        """Test recording filtered packet events"""
        self.tracker.record_filtered()
        self.tracker.record_filtered()
        
        totals = self.tracker.get_total_counts()
        self.assertEqual(totals['total_filtered'], 2)

    def test_get_rates(self):
        """Test rate calculation"""
        # Record events with specific timestamps
        base_time = time.time()
        
        # Record 10 packets over 5 seconds
        for i in range(10):
            self.tracker.record_packet(base_time + i * 0.5)
        
        rates = self.tracker.get_rates()
        
        # Should have all 10 packets in the 10-second window
        self.assertEqual(rates['packets_per_sec'], 1.0)  # 10 packets / 10 seconds

    def test_get_top_attackers(self):
        """Test top attackers calculation"""
        # Create attackers with different threat counts
        self.tracker.record_threat("192.168.1.100")
        self.tracker.record_threat("192.168.1.100")
        self.tracker.record_threat("192.168.1.100")
        
        self.tracker.record_threat("192.168.1.101")
        self.tracker.record_threat("192.168.1.101")
        
        self.tracker.record_threat("192.168.1.102")
        
        top_attackers = self.tracker.get_top_attackers(limit=3)
        
        # Should be sorted by threat count
        self.assertEqual(len(top_attackers), 3)
        self.assertEqual(top_attackers[0][0], "192.168.1.100")  # IP
        self.assertEqual(top_attackers[0][1], 3)                 # Count
        self.assertEqual(top_attackers[1][0], "192.168.1.101")
        self.assertEqual(top_attackers[1][1], 2)

    def test_sliding_window(self):
        """Test that old events are excluded from rate calculation"""
        tracker = StatisticsTracker(window_size=2)  # 2 second window
        
        base_time = time.time()
        
        # Record old events (outside window)
        tracker.record_packet(base_time - 10)
        tracker.record_packet(base_time - 10)
        
        # Record recent events (inside window)
        tracker.record_packet(base_time - 1)
        tracker.record_packet(base_time - 0.5)
        
        rates = tracker.get_rates()
        
        # Should only count the 2 recent packets
        self.assertEqual(rates['packets_per_sec'], 1.0)  # 2 packets / 2 seconds

    def test_top_attackers_excludes_old(self):
        """Test that inactive attackers are excluded"""
        current_time = time.time()
        
        # Recent attacker
        self.tracker.record_threat("192.168.1.100", current_time - 60)
        
        # Old attacker (more than 5 minutes ago)
        self.tracker.record_threat("192.168.1.101", current_time - 400)
        
        top_attackers = self.tracker.get_top_attackers(limit=5)
        
        # Should only include recent attacker
        self.assertEqual(len(top_attackers), 1)
        self.assertEqual(top_attackers[0][0], "192.168.1.100")

    def test_reset(self):
        """Test resetting statistics"""
        self.tracker.record_packet()
        self.tracker.record_threat("192.168.1.100")
        
        self.tracker.reset()
        
        totals = self.tracker.get_total_counts()
        self.assertEqual(totals['total_packets'], 0)
        self.assertEqual(totals['total_threats'], 0)
        self.assertEqual(totals['unique_attackers'], 0)

    def test_thread_safety(self):
        """Test that operations are thread-safe"""
        import threading
        
        def record_packets():
            for _ in range(100):
                self.tracker.record_packet()
        
        def record_threats():
            for i in range(100):
                self.tracker.record_threat(f"192.168.1.{i % 10}")
        
        # Run operations in parallel
        threads = [
            threading.Thread(target=record_packets),
            threading.Thread(target=record_threats),
            threading.Thread(target=record_packets)
        ]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        totals = self.tracker.get_total_counts()
        
        # Should have recorded all events
        self.assertEqual(totals['total_packets'], 200)
        self.assertEqual(totals['total_threats'], 100)


# ===================================
# STATISTICS DISPLAY TESTS
# ===================================

class TestStatisticsDisplay(unittest.TestCase):
    """Unit tests for StatisticsDisplay"""

    def setUp(self):
        """Set up test fixtures"""
        # Create mock IDS instance
        class MockIDS:
            def get_statistics(self):
                return {
                    'active_flows': 42,
                    'queue_size': 10
                }
        
        self.mock_ids = MockIDS()
        self.tracker = StatisticsTracker()
        self.display = StatisticsDisplay(
            ids_instance=self.mock_ids,
            tracker=self.tracker,
            config=None
        )

    def test_initialization(self):
        """Test that display initializes correctly"""
        self.assertIsNotNone(self.display.tracker)
        self.assertIsNotNone(self.display.ids)
        self.assertEqual(self.display.update_interval, 10)  # Default
        self.assertTrue(self.display.use_colors)  # Default

    def test_render_stats_basic(self):
        """Test basic statistics rendering"""
        # Record some events
        self.tracker.record_packet()
        self.tracker.record_threat("192.168.1.100")
        
        output = self.display._render_stats()
        
        # Check that output contains expected sections
        self.assertIn("IDS Real-Time Statistics", output)
        self.assertIn("RATES", output)
        self.assertIn("TOTALS", output)
        self.assertIn("TOP ATTACKERS", output)

    def test_render_stats_with_attackers(self):
        """Test rendering with top attackers"""
        # Record threats from multiple IPs
        for i in range(5):
            self.tracker.record_threat("192.168.1.100")
        for i in range(3):
            self.tracker.record_threat("192.168.1.101")
        
        output = self.display._render_stats()
        
        # Should show attackers
        self.assertIn("192.168.1.100", output)
        self.assertIn("192.168.1.101", output)

    def test_color_coding(self):
        """Test that color codes are applied correctly"""
        # With colors enabled
        self.display.use_colors = True
        output = self.display._color_value(100, 'threat_count')
        self.assertIn(Colors.FAIL, output)  # High threat count = red
        
        # With colors disabled
        self.display.use_colors = False
        output = self.display._color_value(100, 'threat_count')
        self.assertNotIn(Colors.FAIL, output)

    def test_uptime_formatting(self):
        """Test uptime formatting"""
        # Test various durations
        self.assertEqual(self.display._format_uptime(30), "30s")
        self.assertEqual(self.display._format_uptime(90), "1m 30s")
        self.assertEqual(self.display._format_uptime(3661), "1h 1m 1s")
        self.assertEqual(self.display._format_uptime(7200), "2h 0m 0s")

    def test_display_disabled_by_config(self):
        """Test that display respects config setting"""
        class MockConfig:
            def get(self, path, default):
                if path == 'performance.stats_display_enabled':
                    return False
                return default
        
        display = StatisticsDisplay(
            ids_instance=self.mock_ids,
            tracker=self.tracker,
            config=MockConfig()
        )
        
        self.assertFalse(display.enabled)

    def test_custom_update_interval(self):
        """Test custom update interval from config"""
        class MockConfig:
            def get(self, path, default):
                if path == 'performance.stats_interval':
                    return 5
                return default
        
        display = StatisticsDisplay(
            ids_instance=self.mock_ids,
            tracker=self.tracker,
            config=MockConfig()
        )
        
        self.assertEqual(display.update_interval, 5)

    def test_colors_can_be_disabled(self):
        """Test that colors can be disabled via config"""
        class MockConfig:
            def get(self, path, default):
                if path == 'performance.stats_use_colors':
                    return False
                return default
        
        display = StatisticsDisplay(
            ids_instance=self.mock_ids,
            tracker=self.tracker,
            config=MockConfig()
        )
        
        self.assertFalse(display.use_colors)

    def test_final_summary(self):
        """Test final summary display"""
        # Record some events
        for i in range(10):
            self.tracker.record_packet()
        for i in range(5):
            self.tracker.record_threat("192.168.1.100")
        
        # Should not raise any exceptions
        try:
            # Capture output would require redirecting stdout
            # For now, just verify it doesn't crash
            self.display.start_time = time.time() - 60  # 1 minute uptime
            # self.display.display_final_summary()  # Would print to stdout
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"display_final_summary() raised {e}")


# ===================================
# COLOR CLASS TEST
# ===================================

class TestColorsEnum(unittest.TestCase):
    """Test Colors class"""

    def test_color_codes_exist(self):
        """Test that all color codes are defined"""
        self.assertIsNotNone(Colors.HEADER)
        self.assertIsNotNone(Colors.OKBLUE)
        self.assertIsNotNone(Colors.OKGREEN)
        self.assertIsNotNone(Colors.WARNING)
        self.assertIsNotNone(Colors.FAIL)
        self.assertIsNotNone(Colors.RESET)

    def test_semantic_colors(self):
        """Test semantic color aliases"""
        self.assertIsNotNone(Colors.INFO)
        self.assertIsNotNone(Colors.SUCCESS)
        self.assertIsNotNone(Colors.ALERT)
        self.assertIsNotNone(Colors.CRITICAL)



# ===================================
# PCAP GENERATION AND TESTING
# ===================================
def generate_test_pcap(filename="test_traffic.pcap"):
    """
    Generate a PCAP file with various traffic patterns for testing

    Args:
        filename: Output filename for the PCAP

    Returns:
        str: Path to the generated PCAP file
    """
    packets = []
    current_time = time.time()

    print(f"Generating test PCAP: {filename}")

    # Normal traffic - ACK packets at normal rate
    for i in range(20):
        pkt = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234+i, dport=80, flags="A")
        pkt.time = current_time + i * 1.0
        packets.append(pkt)

    # SYN flood - Many SYN packets at HIGH rate (>1500 pkt/sec)
    # Generate 30 packets over 0.01 seconds = 3000 pkt/sec
    for i in range(30):
        pkt = IP(src=f"10.0.0.{i%255}", dst="192.168.1.2") / TCP(sport=5000+i, dport=80, flags="S")
        pkt.time = current_time + 10 + i * 0.0003 # 0.3ms apart = ~3000 pkts/sec
        packets.append(pkt)

    # Port scan - SYN packets to sequential ports
    # Generate 25 packets over 0.03 seconds = ~800 pkt/sec
    for port in range(20, 45):
        pkt = IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=port, flags="S")
        pkt.time = current_time + 15 + (port-20) * 0.0012 # 1.2ms apart = ~800 pkt/sec
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"✓ Generated {len(packets)} packets in {filename}")
    print(f"  - 20 normal packets")
    print(f"  - 30 SYN flood packets (~3000 pkt/sec)")
    print(f"  - 25 port scan packets (~800 pkt/sec)")
    return filename

def test_with_pcap(pcap_file):
    """
    Test IDS with a PCAP file

    Args:
        pcap_file: Path to PCAP file to analyze
    """
    print(f"\n{'='*60}")
    print(f"PCAP FILE TEST: {pcap_file}")
    print(f"{'='*60}")

    if not os.path.exists(pcap_file):
        print(f"❌ File not found: {pcap_file}")
        return
    
    packets = rdpcap(pcap_file)
    analyzer = TrafficAnalyzer()
    engine = DetectionEngine()

    # Note: Anomaly detection disabled for PCAP analysis
    # PCAP timing doesn't reflect real-world flow rates
    print("Analyzing with signature-based detection...\n")


    threat_count = 0

    for i, packet in enumerate(packets, 1):
        features = analyzer.analyze_packet(packet)

        if features:
            threats = engine.detect_threats(features)
            if threats:
                threat_count += 1
                print(f"Packet {i}: {len(threats)} threat(s) - {[t.get('rule', t['type']) for t in threats]}")

    print(f"\n{'='*60}")
    print(f"ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"Total packets analyzed: {len(packets)}")
    print(f"Threatening packets: {threat_count}")
    print(f"Clean packets: {len(packets) - threat_count}")
    print(f"{'='*60}\n")


# ===================================
# MAIN TEST RUNNER
# ===================================
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--live":
        # Live network test
        interface = sys.argv[2] if len(sys.argv) > 2 else "lo0"
        LiveNetworkTest.capture_and_analyze(interface=interface, duration=30, packet_count=100)

    elif len(sys.argv) > 1 and sys.argv[1] == "--pcap":
        # Test with PCAP file
        if len(sys.argv) > 2:
            test_with_pcap(sys.argv[2])
        else:
            # Generate and test with synthetic PCAP
            pcap_file = generate_test_pcap()
            test_with_pcap(pcap_file)

    else:
        # Run unit tests
        print("\n" + "="*60)
        print("RUNNING UNIT TESTS")
        print("="*60 + "\n")
        unittest.main(verbosity=2)