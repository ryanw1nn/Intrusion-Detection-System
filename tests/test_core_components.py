"""
Comprehensive tests for core IDS components:
- TrafficAnalyzer
- DetectionEngine  
- PacketCapture
"""

import unittest
from scapy.all import IP, TCP
from ids.traffic_analyzer import TrafficAnalyzer
from ids.detection_engine import DetectionEngine
from ids.packet_capture import PacketCapture
import numpy as np
import time
import threading


class TestTrafficAnalyzer(unittest.TestCase):
    """Comprehensive tests for TrafficAnalyzer"""

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
        self.assertIn('flow_duration', features)
        self.assertIn('byte_rate', features)
        self.assertIn('window_size', features)
        self.assertIn('packet_count', features)

    def test_flow_tracking_same_flow(self):
        """Test that same flow is tracked correctly"""
        packet1 = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        packet1.time = time.time()

        self.analyzer.analyze_packet(packet1)
        self.assertEqual(self.analyzer.get_flow_count(), 1)

        # Same flow - should not create new flow
        packet2 = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        packet2.time = time.time()
        features = self.analyzer.analyze_packet(packet2)
        
        self.assertEqual(self.analyzer.get_flow_count(), 1)
        self.assertEqual(features['packet_count'], 2)  # Second packet in flow

    def test_flow_tracking_different_flows(self):
        """Test that different flows are tracked separately"""
        packet1 = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        packet1.time = time.time()
        self.analyzer.analyze_packet(packet1)

        # Different source
        packet2 = IP(src="192.168.1.3", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        packet2.time = time.time()
        self.analyzer.analyze_packet(packet2)

        # Different port
        packet3 = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=5678, dport=80)
        packet3.time = time.time()
        self.analyzer.analyze_packet(packet3)

        self.assertEqual(self.analyzer.get_flow_count(), 3)

    def test_max_flows_limit_enforced(self):
        """Test that max flows limit is enforced with LRU eviction"""
        analyzer = TrafficAnalyzer(max_flows=5)

        # Create 10 different flows
        for i in range(10):
            packet = IP(src=f"192.168.1.{i}", dst="192.168.1.100") / TCP(sport=1000+i, dport=80)
            packet.time = time.time()
            analyzer.analyze_packet(packet)

        # Should only keep 5 flows (LRU eviction)
        self.assertEqual(analyzer.get_flow_count(), 5)

    def test_flow_cleanup_by_timeout(self):
        """Test that old flows are cleaned up after timeout"""
        analyzer = TrafficAnalyzer(max_flows=100, flow_timeout=2)

        packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        packet.time = time.time()
        analyzer.analyze_packet(packet)

        self.assertEqual(analyzer.get_flow_count(), 1)

        # Wait for timeout
        time.sleep(3)

        # Trigger cleanup
        removed = analyzer.cleanup_old_flows()
        self.assertEqual(removed, 1)
        self.assertEqual(analyzer.get_flow_count(), 0)

    def test_invalid_packet_handling(self):
        """Test handling of non-TCP/IP packets"""
        # Packet without TCP layer
        packet = IP(src="192.168.1.1", dst="192.168.1.2")
        features = self.analyzer.analyze_packet(packet)
        self.assertIsNone(features)

    def test_feature_values_valid(self):
        """Test that extracted features have valid values"""
        packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="S")
        packet.time = time.time()

        features = self.analyzer.analyze_packet(packet)

        self.assertGreater(features['packet_size'], 0)
        self.assertGreater(features['packet_rate'], 0)
        self.assertGreater(features['byte_rate'], 0)
        self.assertGreaterEqual(features['flow_duration'], 0)
        self.assertGreaterEqual(features['tcp_flags'], 0)
        self.assertGreaterEqual(features['window_size'], 0)
        self.assertEqual(features['packet_count'], 1)

    def test_get_flow_info(self):
        """Test getting flow information"""
        for i in range(5):
            packet = IP(src=f"192.168.1.{i}", dst="192.168.1.100") / TCP(sport=1234, dport=80)
            packet.time = time.time()
            self.analyzer.analyze_packet(packet)

        flows = self.analyzer.get_flow_info(limit=3)
        self.assertEqual(len(flows), 3)
        self.assertIsInstance(flows, list)

    def test_reset(self):
        """Test resetting the analyzer"""
        packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        packet.time = time.time()
        self.analyzer.analyze_packet(packet)

        self.assertEqual(self.analyzer.get_flow_count(), 1)

        self.analyzer.reset()
        self.assertEqual(self.analyzer.get_flow_count(), 0)


class TestDetectionEngine(unittest.TestCase):
    """Comprehensive tests for DetectionEngine"""
    
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
            'packet_rate': 2000,  # Above threshold (1500)
            'byte_rate': 120000,
            'tcp_flags': 2,  # SYN flag only
            'flow_duration': 1.0,
            'window_size': 8192,
            'packet_count': 20  # Above minimum (15)
        }

        threats = self.engine.detect_threats(features)

        self.assertGreater(len(threats), 0)
        self.assertTrue(any(t['rule'] == 'syn_flood' for t in threats if t['type'] == 'signature'))
        
        # Check threat structure
        syn_flood_threat = next(t for t in threats if t.get('rule') == 'syn_flood')
        self.assertEqual(syn_flood_threat['severity'], 'high')
        self.assertEqual(syn_flood_threat['confidence'], 1.0)

    def test_port_scan_detection(self):
        """Test port scan signature detection"""
        features = {
            'packet_size': 60,
            'packet_rate': 600,  # Above threshold (500)
            'byte_rate': 36000,
            'tcp_flags': 2,  # SYN flag
            'flow_duration': 0.3,  # Short duration
            'window_size': 8192,
            'packet_count': 20  # Above minimum
        }

        threats = self.engine.detect_threats(features)

        self.assertGreater(len(threats), 0)
        self.assertTrue(any(t['rule'] == 'port_scan' for t in threats if t['type'] == 'signature'))
        
        # Check threat structure
        port_scan_threat = next(t for t in threats if t.get('rule') == 'port_scan')
        self.assertEqual(port_scan_threat['severity'], 'medium')

    def test_large_packet_detection(self):
        """Test large packet detection"""
        features = {
            'packet_size': 2000,  # Above default threshold (1500)
            'packet_rate': 10,
            'byte_rate': 20000,
            'tcp_flags': 16,  # ACK flag
            'flow_duration': 1.0,
            'window_size': 8192,
            'packet_count': 1
        }

        threats = self.engine.detect_threats(features)
        
        # Should detect large packet
        self.assertTrue(any(t['rule'] == 'large_packet' for t in threats if t['type'] == 'signature'))

    def test_normal_traffic_no_alerts(self):
        """Test that normal traffic doesn't trigger alerts"""
        features = {
            'packet_size': 100,
            'packet_rate': 10,
            'byte_rate': 1000,
            'tcp_flags': 16,  # ACK flag (normal)
            'flow_duration': 1.0,
            'window_size': 8192,
            'packet_count': 5
        }

        threats = self.engine.detect_threats(features)

        # Should have no signature-based threats
        signature_threats = [t for t in threats if t['type'] == 'signature']
        self.assertEqual(len(signature_threats), 0)

    def test_anomaly_detection_trained(self):
        """Test anomaly detection on unusual traffic (when trained)"""
        features = {
            'packet_size': 9999,  # Very unusual
            'packet_rate': 1000,
            'byte_rate': 9999000,
            'tcp_flags': 16,
            'flow_duration': 1.0,
            'window_size': 8192
        }

        threats = self.engine.detect_threats(features)

        # Should detect anomaly
        anomaly_threats = [t for t in threats if t['type'] == 'anomaly']
        self.assertGreater(len(anomaly_threats), 0)
        
        # Check anomaly structure
        anomaly = anomaly_threats[0]
        self.assertIn('score', anomaly)
        self.assertIn('confidence', anomaly)
        self.assertIn('severity', anomaly)

    def test_below_threshold_no_alert(self):
        """Test that traffic below thresholds doesn't trigger alerts"""
        features = {
            'packet_size': 60,
            'packet_rate': 1000,  # Below SYN flood threshold (1500)
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

    def test_insufficient_packets_no_alert(self):
        """Test that flows with too few packets don't trigger alerts"""
        features = {
            'packet_size': 60,
            'packet_rate': 2000,  # Above threshold
            'byte_rate': 120000,
            'tcp_flags': 2,
            'flow_duration': 1.0,
            'window_size': 8192,
            'packet_count': 10  # Below minimum (15)
        }

        threats = self.engine.detect_threats(features)

        # Should NOT detect (insufficient packets)
        syn_flood_threats = [t for t in threats if t.get('rule') == 'syn_flood']
        self.assertEqual(len(syn_flood_threats), 0)

    def test_add_custom_signature_rule(self):
        """Test adding custom signature rules"""
        def custom_rule(features):
            return features['packet_size'] > 5000

        self.engine.add_signature_rule(
            name='jumbo_packet',
            condition=custom_rule,
            severity='medium',
            description='Jumbo packet detected'
        )

        # Test with large packet
        features = {
            'packet_size': 6000,
            'packet_rate': 10,
            'byte_rate': 60000,
            'tcp_flags': 16,
            'flow_duration': 1.0,
            'window_size': 8192
        }

        threats = self.engine.detect_threats(features)
        
        # Should detect custom rule
        custom_threats = [t for t in threats if t.get('rule') == 'jumbo_packet']
        self.assertEqual(len(custom_threats), 1)

    def test_remove_signature_rule(self):
        """Test removing signature rules"""
        # Add a rule
        self.engine.add_signature_rule(
            name='test_rule',
            condition=lambda f: True,
            severity='low'
        )

        # Remove it
        result = self.engine.remove_signature_rule('test_rule')
        self.assertTrue(result)

        # Try to remove non-existent rule
        result = self.engine.remove_signature_rule('nonexistent')
        self.assertFalse(result)

    def test_get_statistics(self):
        """Test getting engine statistics"""
        stats = self.engine.get_statistics()

        self.assertIn('is_trained', stats)
        self.assertIn('signature_rules_count', stats)
        self.assertIn('available_rules', stats)
        self.assertIn('thresholds', stats)
        
        self.assertTrue(stats['is_trained'])
        self.assertGreater(stats['signature_rules_count'], 0)

    def test_reset(self):
        """Test resetting the detection engine"""
        # Record some threats (this would normally populate connection tracker)
        self.engine.reset()
        
        stats = self.engine.get_statistics()
        self.assertEqual(stats['tracked_connections'], 0)


class TestPacketCapture(unittest.TestCase):
    """Tests for PacketCapture component"""

    def setUp(self):
        self.capture = PacketCapture(queue_size=100)

    def test_initialization(self):
        """Test PacketCapture initialization"""
        self.assertIsNotNone(self.capture.packet_queue)
        self.assertEqual(self.capture.packet_queue.maxsize, 100)
        self.assertFalse(self.capture.stop_capture.is_set())
        self.assertIsNone(self.capture.capture_thread)

    def test_packet_callback_valid_packet(self):
        """Test packet callback with valid TCP/IP packet"""
        packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        
        # Call callback
        self.capture.packet_callback(packet)
        
        # Check packet was queued
        self.assertEqual(self.capture.get_queue_size(), 1)
        
        # Retrieve and verify
        queued_packet = self.capture.packet_queue.get_nowait()
        self.assertEqual(queued_packet[IP].src, "192.168.1.1")

    def test_packet_callback_invalid_packet(self):
        """Test packet callback with non-TCP packet"""
        packet = IP(src="192.168.1.1", dst="192.168.1.2")  # No TCP
        
        self.capture.packet_callback(packet)
        
        # Should not be queued
        self.assertEqual(self.capture.get_queue_size(), 0)

    def test_queue_full_handling(self):
        """Test handling of full queue"""
        small_capture = PacketCapture(queue_size=2)
        
        # Fill queue
        for i in range(3):
            packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234+i, dport=80)
            small_capture.packet_callback(packet)
        
        # Queue should be full (maxsize=2)
        self.assertEqual(small_capture.get_queue_size(), 2)

    def test_stop_without_start(self):
        """Test stopping capture that was never started"""
        # Should not crash
        self.capture.stop()
        self.assertTrue(self.capture.stop_capture.is_set())

    def test_get_queue_size(self):
        """Test getting current queue size"""
        self.assertEqual(self.capture.get_queue_size(), 0)
        
        packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        self.capture.packet_callback(packet)
        
        self.assertEqual(self.capture.get_queue_size(), 1)

    def tearDown(self):
        """Clean up after each test"""
        self.capture.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)