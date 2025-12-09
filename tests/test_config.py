"""
Comprehensive tests for configuration loading:
- YAML parsing
- Default values
- Validation
- CLI overrides
"""

import unittest
from ids.config_loader import ConfigLoader, load_config
import tempfile
import yaml
import os


class TestConfigLoaderBasic(unittest.TestCase):
    """Basic configuration loading tests"""

    def test_load_defaults_when_no_file(self):
        """Test that defaults are loaded when config file doesn't exist"""
        with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix='.yaml') as f:
            config_path = f.name + "_nonexistent"
        
        config = ConfigLoader(config_path=config_path)
        
        # Should load defaults
        self.assertEqual(config.get('network.interface'), 'auto')
        self.assertEqual(config.get('network.queue_size'), 1000)

    def test_load_from_file(self):
        """Test loading configuration from YAML file"""
        config_data = {
            'network': {
                'interface': 'eth0',
                'queue_size': 2000
            },
            'detection': {
                'syn_flood': {
                    'rate_threshold': 2000
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            config = ConfigLoader(config_path=config_path)
            
            self.assertEqual(config.get('network.interface'), 'eth0')
            self.assertEqual(config.get('network.queue_size'), 2000)
            self.assertEqual(config.get('detection.syn_flood.rate_threshold'), 2000)
        finally:
            os.unlink(config_path)

    def test_partial_config_uses_defaults(self):
        """Test that missing values use defaults"""
        config_data = {
            'network': {
                'interface': 'eth0'
                # queue_size not specified
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            config = ConfigLoader(config_path=config_path)
            
            # Should use custom value
            self.assertEqual(config.get('network.interface'), 'eth0')
            # Should use default
            self.assertEqual(config.get('network.queue_size'), 1000)
        finally:
            os.unlink(config_path)

    def test_get_with_dot_notation(self):
        """Test getting values with dot notation"""
        config = ConfigLoader()
        
        # Nested access
        value = config.get('detection.syn_flood.rate_threshold')
        self.assertEqual(value, 1500)
        
        # Top-level access
        network = config.get('network')
        self.assertIsInstance(network, dict)

    def test_get_with_default(self):
        """Test get with default value"""
        config = ConfigLoader()
        
        # Non-existent key should return default
        value = config.get('nonexistent.key', 'default_value')
        self.assertEqual(value, 'default_value')


class TestConfigOverrides(unittest.TestCase):
    """Test configuration overrides"""

    def test_override_value(self):
        """Test overriding configuration values"""
        config = ConfigLoader()
        
        original = config.get('network.interface')
        config.override('network.interface', 'en0')
        
        self.assertNotEqual(original, 'en0')
        self.assertEqual(config.get('network.interface'), 'en0')

    def test_override_nested_value(self):
        """Test overriding nested values"""
        config = ConfigLoader()
        
        config.override('detection.syn_flood.rate_threshold', 3000)
        
        self.assertEqual(config.get('detection.syn_flood.rate_threshold'), 3000)

    def test_override_creates_path(self):
        """Test that override creates missing paths"""
        config = ConfigLoader()
        
        config.override('new.nested.key', 'value')
        
        self.assertEqual(config.get('new.nested.key'), 'value')

    def test_cli_overrides(self):
        """Test CLI overrides via load_config function"""
        cli_overrides = {
            'network.interface': 'wlan0',
            'detection.syn_flood.rate_threshold': 2500
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            yaml.dump({'network': {'interface': 'eth0'}}, f)
            config_path = f.name
        
        try:
            config = load_config(config_path, cli_overrides)
            
            # CLI override should win
            self.assertEqual(config.get('network.interface'), 'wlan0')
            self.assertEqual(config.get('detection.syn_flood.rate_threshold'), 2500)
        finally:
            os.unlink(config_path)


class TestConfigValidation(unittest.TestCase):
    """Test configuration validation"""

    def test_invalid_severity_uses_default(self):
        """Test that invalid severity values are corrected"""
        config_data = {
            'detection': {
                'port_scan': {
                    'severity': 'invalid_severity'
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            config = ConfigLoader(config_path=config_path)
            
            # Should use default 'medium'
            severity = config.get('detection.port_scan.severity')
            self.assertIn(severity, ['low', 'medium', 'high'])
        finally:
            os.unlink(config_path)

    def test_negative_queue_size_uses_default(self):
        """Test that negative queue size is rejected"""
        config_data = {
            'network': {
                'queue_size': -100
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            config = ConfigLoader(config_path=config_path)
            
            # Should use default 1000
            self.assertEqual(config.get('network.queue_size'), 1000)
        finally:
            os.unlink(config_path)

    def test_invalid_log_level_uses_default(self):
        """Test that invalid log level is rejected"""
        config_data = {
            'logging': {
                'level': 'INVALID_LEVEL'
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            yaml.dump(config_data, f)
            config_path = f.name
        
        try:
            config = ConfigLoader(config_path=config_path)
            
            # Should use default 'INFO'
            self.assertEqual(config.get('logging.level'), 'INFO')
        finally:
            os.unlink(config_path)


class TestConfigHelpers(unittest.TestCase):
    """Test configuration helper methods"""

    def test_get_detection_config(self):
        """Test getting detection rule config"""
        config = ConfigLoader()
        
        syn_flood_config = config.get_detection_config('syn_flood')
        
        self.assertIsInstance(syn_flood_config, dict)
        self.assertIn('rate_threshold', syn_flood_config)
        self.assertIn('severity', syn_flood_config)

    def test_is_rule_enabled(self):
        """Test checking if rule is enabled"""
        config = ConfigLoader()
        
        self.assertTrue(config.is_rule_enabled('syn_flood'))
        self.assertTrue(config.is_rule_enabled('port_scan'))

    def test_get_whitelist(self):
        """Test getting whitelist"""
        config = ConfigLoader()
        
        whitelist = config.get_whitelist()
        
        self.assertIsInstance(whitelist, list)
        self.assertIn('127.0.0.1', whitelist)

    def test_get_blacklist(self):
        """Test getting blacklist"""
        config = ConfigLoader()
        
        blacklist = config.get_blacklist()
        
        self.assertIsInstance(blacklist, list)

    def test_get_whitelist_ports(self):
        """Test getting whitelisted ports"""
        config = ConfigLoader()
        
        ports = config.get_whitelist_ports()
        
        self.assertIsInstance(ports, list)


class TestConfigSaveLoad(unittest.TestCase):
    """Test saving and loading configuration"""

    def test_save_config(self):
        """Test saving configuration to file"""
        config = ConfigLoader()
        config.override('network.interface', 'test_interface')
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            save_path = f.name
        
        try:
            config.save_config(save_path)
            
            # Load and verify
            with open(save_path, 'r') as f:
                saved_data = yaml.safe_load(f)
            
            self.assertEqual(saved_data['network']['interface'], 'test_interface')
        finally:
            if os.path.exists(save_path):
                os.unlink(save_path)

    def test_string_representation(self):
        """Test string representation of config"""
        config = ConfigLoader()
        
        config_str = str(config)
        
        self.assertIsInstance(config_str, str)
        self.assertIn('network', config_str)


class TestConfigErrorHandling(unittest.TestCase):
    """Test error handling in configuration"""

    def test_invalid_yaml_uses_defaults(self):
        """Test that invalid YAML falls back to defaults"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            f.write("invalid: yaml: content: [")
            config_path = f.name
        
        try:
            config = ConfigLoader(config_path=config_path)
            
            # Should load defaults
            self.assertEqual(config.get('network.queue_size'), 1000)
        finally:
            os.unlink(config_path)

    def test_empty_yaml_uses_defaults(self):
        """Test that empty YAML file uses defaults"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            config_path = f.name
        
        try:
            config = ConfigLoader(config_path=config_path)
            
            # Should load defaults
            self.assertEqual(config.get('network.queue_size'), 1000)
        finally:
            os.unlink(config_path)


class TestConfigIntegrationWithComponents(unittest.TestCase):
    """Test configuration integration with IDS components"""

    def test_detection_engine_loads_config(self):
        """Test that DetectionEngine loads thresholds from config"""
        from ids.detection_engine import DetectionEngine
        
        config = ConfigLoader()
        config.override('detection.syn_flood.rate_threshold', 3000)
        
        engine = DetectionEngine(config=config)
        
        self.assertEqual(engine.syn_flood_rate, 3000)

    def test_detection_engine_without_config(self):
        """Test that DetectionEngine works without config"""
        from ids.detection_engine import DetectionEngine
        
        engine = DetectionEngine(config=None)
        
        # Should use defaults
        self.assertEqual(engine.syn_flood_rate, 1500)
        self.assertEqual(engine.port_scan_rate, 500)

    def test_packet_filter_loads_config(self):
        """Test that PacketFilter loads rules from config"""
        from ids.packet_filter import PacketFilter
        
        config = ConfigLoader()
        config.override('filtering.whitelist', ['10.0.0.1', '192.168.1.0/24'])
        
        pfilter = PacketFilter(config=config)
        
        stats = pfilter.get_statistics()
        self.assertEqual(stats['whitelist_entries'], 2)


class TestDefaultConfiguration(unittest.TestCase):
    """Test default configuration values"""

    def test_default_network_settings(self):
        """Test default network settings"""
        config = ConfigLoader()
        
        self.assertEqual(config.get('network.interface'), 'auto')
        self.assertEqual(config.get('network.queue_size'), 1000)
        self.assertEqual(config.get('network.bpf_filter'), '')

    def test_default_detection_settings(self):
        """Test default detection settings"""
        config = ConfigLoader()
        
        self.assertEqual(config.get('detection.syn_flood.rate_threshold'), 1500)
        self.assertEqual(config.get('detection.port_scan.rate_threshold'), 500)
        self.assertTrue(config.get('detection.syn_flood.enabled'))

    def test_default_alerting_settings(self):
        """Test default alerting settings"""
        config = ConfigLoader()
        
        self.assertEqual(config.get('alerting.log_file'), 'ids_alerts.log')
        self.assertEqual(config.get('alerting.deduplication_window'), 60)
        self.assertEqual(config.get('alerting.min_severity'), 'low')

    def test_default_performance_settings(self):
        """Test default performance settings"""
        config = ConfigLoader()
        
        self.assertEqual(config.get('performance.stats_interval'), 10)
        self.assertTrue(config.get('performance.stats_display_enabled'))


if __name__ == "__main__":
    unittest.main(verbosity=2)