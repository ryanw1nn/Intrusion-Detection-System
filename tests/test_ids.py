"""
Comprehensive test suite for the Network IDS
Includes unit tests and live network testing capability
"""

import unittest
from scapy.all import IP, TCP, wrpcap, rdpcap
from ids.traffic_analyzer import TrafficAnalyzer
from ids.detection_engine import DetectionEngine
import numpy as np
import time
import os

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
            'packet_rate': 150, # high rate
            'byte_rate': 900,
            'tcp_flags': 2, # SYN flag
            'flow_duration': 1.0,
            'window_size': 8192
        }

        threats = self.engine.detect_threats(features)

        self.assertTrue(len(threats) > 0)
        self.assertTrue(any(t['rule'] == 'syn_flood' for t in threats if t['type'] == 'signature'))

    def test_port_scan_detection(self):
        """Test port scan signature detection"""
        features = {
            'packet_size': 60, # small packet
            'packet_rate': 60, # high rate
            'byte_rate': 3600,
            'tcp_flags': 2,
            'flow_duration': 1.0,
            'window_size': 8192
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

        # Generate some baseline training data
        print("Training anomaly detector with synthetic baseline...")
        #normal_data = np.random.normal(loc=[100, 10, 1000], scale=[20, 3,200], size=(50, 3))
        #engine.train_anomaly_detector(normal_data)
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

def generate_test_pcap(filename="test_traffic.pcap"):
    """
    Generate a PCAP file with various traffic patterns for testing
    """
    packets = []
    current_time = time.time()

    print(f"Generating test PCAP: {filename}")

    # Normal traffic
    for i in range(20):
        pkt = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234+i, dport=80, flags="A")
        pkt.time = current_time + i * 1.0
        packets.append(pkt)

    # SYN flood
    for i in range(50):
        pkt = IP(src=f"10.0.0.{i%255}", dst="192.168.1.2") / TCP(sport=5000+i, dport=80, flags="S")
        pkt.time = current_time + 10 + i * 0.01
        packets.append(pkt)

    # Port scan
    for port in range(20, 100):
        pkt = IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=port, flags="S")
        pkt.time = current_time + 15 + (port-20) * 0.02
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"✓ Generated {len(packets)} packets in {filename}")
    return filename

def test_with_pcap(pcap_file):
    """
    Test IDS with a PCAP file
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

    # Train detector
    normal_data = np.array([[100,10,1000], [120,15,1500], [80,5,800]])
    engine.train_anomaly_detector(normal_data)
    print("Anomaly detection disabled for live test (signature-based only)")


    threat_count = 0

    for i, packet in enumerate(packets, 1):
        features = analyzer.analyze_packet(packet)

        if features:

            # DEBUG OUTPUT
            if i in [1, 21, 71]:
                print(f"\n=== DEBUG Packet {i} ===")
                print(f"  IP: {packet[IP].src} -> {packet[IP].dst}")
                print(f"  Ports: {packet[TCP].sport} -> {packet[TCP].dport}")
                print(f"  TCP Flags: {packet[TCP].flags} (int: {features['tcp_flags']})")
                print(f"  Packet size: {features['packet_size']}")
                print(f"  Packet count in flow: {features['packet_count']}")
                print(f"  Flow duration: {features['flow_duration']}")
                print(f"  Packet rate: {features['packet_rate']}")

            threats = engine.detect_threats(features)
            if threats:
                threat_count += 1
                print(f"Packet {i}: {len(threats)} threat(s) - {[t.get('rule', t['type']) for t in threats]}")

    print(f"\n{'='*60}")
    print(f"Analyzed {len(packets)} packets")
    print(f"Detected {threat_count} threatening packets")
    print(f"{'='*60}\n")

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