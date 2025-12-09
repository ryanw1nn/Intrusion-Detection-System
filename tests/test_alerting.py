"""
Comprehensive tests for alert system:
- Alert generation
- Deduplication
- Rate limiting
- Statistics tracking
"""

import unittest
from ids.alert_system import AlertSystem
from ids.config_loader import ConfigLoader
import tempfile
import os
import time
import json


class TestAlertGeneration(unittest.TestCase):
    """Test basic alert generation"""

    def setUp(self):
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.temp_log.close()
        self.log_file = self.temp_log.name
        self.alert_system = AlertSystem(log_file=self.log_file)
    
    def tearDown(self):
        if os.path.exists(self.log_file):
            os.unlink(self.log_file)

    def test_generate_simple_alert(self):
        """Test generating a simple alert"""
        threat = {
            'type': 'signature',
            'rule': 'syn_flood',
            'confidence': 0.9,
            'severity': 'high'
        }
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        result = self.alert_system.generate_alert(threat, packet_info)
        
        self.assertTrue(result)
        stats = self.alert_system.get_statistics()
        self.assertEqual(stats['total_alerts_generated'], 1)

    def test_alert_written_to_file(self):
        """Test that alerts are written to log file"""
        threat = {
            'type': 'signature',
            'rule': 'port_scan',
            'confidence': 1.0,
            'severity': 'medium'
        }
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        self.alert_system.generate_alert(threat, packet_info)
        
        # Read log file
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn('port_scan', content)
            self.assertIn('192.168.1.100', content)

    def test_alert_json_format(self):
        """Test that alerts are valid JSON"""
        threat = {
            'type': 'signature',
            'rule': 'syn_flood',
            'confidence': 0.9,
            'severity': 'high'
        }
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        self.alert_system.generate_alert(threat, packet_info)
        
        # Read and parse log file
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
            # Find the JSON part (after the log prefix)
            for line in lines:
                if '{' in line:
                    json_start = line.index('{')
                    json_str = line[json_start:]
                    alert_data = json.loads(json_str)
                    
                    self.assertIn('timestamp', alert_data)
                    self.assertIn('threat_type', alert_data)
                    self.assertIn('rule', alert_data)
                    self.assertIn('severity', alert_data)
                    self.assertEqual(alert_data['rule'], 'syn_flood')


class TestAlertDeduplication(unittest.TestCase):
    """Test alert deduplication functionality"""

    def setUp(self):
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.temp_log.close()
        self.log_file = self.temp_log.name
        self.alert_system = AlertSystem(log_file=self.log_file)
    
    def tearDown(self):
        if os.path.exists(self.log_file):
            os.unlink(self.log_file)

    def test_first_alert_not_suppressed(self):
        """Test that the first alert for a flow is not suppressed"""
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        result = self.alert_system.generate_alert(threat, packet_info)
        
        self.assertTrue(result)
        stats = self.alert_system.get_statistics()
        self.assertEqual(stats['total_alerts_generated'], 1)
        self.assertEqual(stats['total_alerts_suppressed'], 0)

    def test_duplicate_alert_suppressed(self):
        """Test that duplicate alerts within deduplication window are suppressed"""
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        # First alert
        result1 = self.alert_system.generate_alert(threat, packet_info)
        self.assertTrue(result1)
        
        # Duplicate alert (within 60 seconds)
        result2 = self.alert_system.generate_alert(threat, packet_info)
        self.assertFalse(result2)
        
        # Third duplicate
        result3 = self.alert_system.generate_alert(threat, packet_info)
        self.assertFalse(result3)
        
        stats = self.alert_system.get_statistics()
        self.assertEqual(stats['total_alerts_generated'], 1)
        self.assertEqual(stats['total_alerts_suppressed'], 2)

    def test_different_flows_not_suppressed(self):
        """Test that alerts for different flows are not suppressed"""
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        
        # Flow 1
        packet_info1 = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        # Flow 2 (different destination)
        packet_info2 = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.2',  # Different
            'source_port': 12345,
            'destination_port': 80
        }
        
        result1 = self.alert_system.generate_alert(threat, packet_info1)
        result2 = self.alert_system.generate_alert(threat, packet_info2)
        
        self.assertTrue(result1)
        self.assertTrue(result2)
        
        stats = self.alert_system.get_statistics()
        self.assertEqual(stats['total_alerts_generated'], 2)
        self.assertEqual(stats['unique_flows_alerted'], 2)

    def test_different_threat_types_not_suppressed(self):
        """Test that different threat types on same flow are not suppressed"""
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        threat1 = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        threat2 = {'type': 'signature', 'rule': 'port_scan', 'confidence': 0.8, 'severity': 'medium'}
        
        result1 = self.alert_system.generate_alert(threat1, packet_info)
        result2 = self.alert_system.generate_alert(threat2, packet_info)
        
        self.assertTrue(result1)
        self.assertTrue(result2)

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
        
        # Wait for window to expire
        time.sleep(1.5)
        
        # Alert after window - should be allowed
        result2 = alert_system.generate_alert(threat, packet_info)
        self.assertTrue(result2)
        
        stats = alert_system.get_statistics()
        self.assertEqual(stats['total_alerts_generated'], 2)
        self.assertEqual(stats['total_alerts_suppressed'], 0)

    def test_deduplication_can_be_disabled(self):
        """Test that deduplication can be disabled via config"""
        config = ConfigLoader()
        config.override('alerting.deduplication_window', 0)
        
        alert_system = AlertSystem(log_file=self.log_file, config=config)
        
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        # All alerts should be generated
        result1 = alert_system.generate_alert(threat, packet_info)
        result2 = alert_system.generate_alert(threat, packet_info)
        result3 = alert_system.generate_alert(threat, packet_info)
        
        self.assertTrue(result1)
        self.assertTrue(result2)
        self.assertTrue(result3)


class TestRateLimiting(unittest.TestCase):
    """Test rate limiting functionality"""

    def setUp(self):
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.temp_log.close()
        self.log_file = self.temp_log.name
        self.alert_system = AlertSystem(log_file=self.log_file)
    
    def tearDown(self):
        if os.path.exists(self.log_file):
            os.unlink(self.log_file)

    def test_rate_limit_enforcement(self):
        """Test that rate limiting prevents alert storms"""
        alert_system = AlertSystem(log_file=self.log_file)
        alert_system.rate_limit_per_minute = 10  # Low limit for testing
        
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        
        # Generate 15 alerts from different flows
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

    def test_rate_limit_with_config(self):
        """Test that rate limit settings are loaded from config"""
        config = ConfigLoader()
        config.override('alerting.rate_limit_per_minute', 5)
        
        alert_system = AlertSystem(log_file=self.log_file, config=config)
        
        self.assertEqual(alert_system.rate_limit_per_minute, 5)


class TestAlertStatistics(unittest.TestCase):
    """Test alert system statistics"""

    def setUp(self):
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.temp_log.close()
        self.log_file = self.temp_log.name
        self.alert_system = AlertSystem(log_file=self.log_file)
    
    def tearDown(self):
        if os.path.exists(self.log_file):
            os.unlink(self.log_file)

    def test_statistics_initialization(self):
        """Test that statistics are initialized"""
        stats = self.alert_system.get_statistics()
        
        self.assertEqual(stats['total_alerts_generated'], 0)
        self.assertEqual(stats['total_alerts_suppressed'], 0)
        self.assertEqual(stats['total_rate_limited'], 0)
        self.assertEqual(stats['unique_flows_alerted'], 0)

    def test_suppression_rate_calculation(self):
        """Test suppression rate calculation"""
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        # Generate 1 alert + 3 duplicates
        self.alert_system.generate_alert(threat, packet_info)
        self.alert_system.generate_alert(threat, packet_info)
        self.alert_system.generate_alert(threat, packet_info)
        self.alert_system.generate_alert(threat, packet_info)
        
        stats = self.alert_system.get_statistics()
        
        # 1 generated, 3 suppressed = 75% suppression rate
        self.assertEqual(stats['total_alerts_generated'], 1)
        self.assertEqual(stats['total_alerts_suppressed'], 3)
        self.assertEqual(stats['suppression_rate'], 75.0)

    def test_get_flow_history(self):
        """Test getting flow history"""
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        
        for i in range(5):
            packet_info = {
                'source_ip': f'192.168.1.{i}',
                'destination_ip': '10.0.0.1',
                'source_port': 12345,
                'destination_port': 80
            }
            self.alert_system.generate_alert(threat, packet_info)
        
        history = self.alert_system.get_flow_history(limit=3)
        self.assertEqual(len(history), 3)

    def test_reset_statistics(self):
        """Test resetting statistics"""
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        self.alert_system.generate_alert(threat, packet_info)
        
        self.alert_system.reset_statistics()
        
        stats = self.alert_system.get_statistics()
        self.assertEqual(stats['total_alerts_generated'], 0)

    def test_cleanup_old_flows(self):
        """Test cleanup of old flow history"""
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        self.alert_system.generate_alert(threat, packet_info)
        
        # Cleanup with 0 second max age (remove everything)
        self.alert_system.cleanup_old_flows(max_age_seconds=0)
        
        stats = self.alert_system.get_statistics()
        self.assertEqual(stats['active_flows_tracked'], 0)


class TestAlertMetadata(unittest.TestCase):
    """Test alert metadata and context"""

    def setUp(self):
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.temp_log.close()
        self.log_file = self.temp_log.name
        self.alert_system = AlertSystem(log_file=self.log_file)
    
    def tearDown(self):
        if os.path.exists(self.log_file):
            os.unlink(self.log_file)

    def test_alert_includes_all_fields(self):
        """Test that alerts include all required fields"""
        threat = {
            'type': 'signature',
            'rule': 'syn_flood',
            'confidence': 0.9,
            'severity': 'high',
            'description': 'Test threat'
        }
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        self.alert_system.generate_alert(threat, packet_info)
        
        # Read and parse log
        with open(self.log_file, 'r') as f:
            for line in f:
                if '{' in line:
                    json_start = line.index('{')
                    alert = json.loads(line[json_start:])
                    
                    # Required fields
                    self.assertIn('timestamp', alert)
                    self.assertIn('threat_type', alert)
                    self.assertIn('rule', alert)
                    self.assertIn('severity', alert)
                    self.assertIn('confidence', alert)
                    self.assertIn('source_ip', alert)
                    self.assertIn('source_port', alert)
                    self.assertIn('destination_ip', alert)
                    self.assertIn('destination_port', alert)
                    self.assertIn('status', alert)
                    self.assertIn('alert_count', alert)

    def test_ongoing_alert_status(self):
        """Test that repeated alerts are marked as ongoing"""
        threat = {'type': 'signature', 'rule': 'syn_flood', 'confidence': 0.9, 'severity': 'high'}
        packet_info = {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 12345,
            'destination_port': 80
        }
        
        # First alert
        self.alert_system.generate_alert(threat, packet_info)
        
        # Wait for window to expire
        self.alert_system.deduplication_window = 0.1
        time.sleep(0.2)
        
        # Second alert
        self.alert_system.generate_alert(threat, packet_info)
        
        # Read log and check last alert
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
            if len(lines) >= 2:
                # Second alert should have status='ongoing'
                json_start = lines[-1].index('{')
                alert = json.loads(lines[-1][json_start:])
                self.assertEqual(alert['status'], 'ongoing')
                self.assertGreater(alert['alert_count'], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)