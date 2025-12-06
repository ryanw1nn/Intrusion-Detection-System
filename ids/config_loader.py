"""
Configuration loader for the IDS.

Loads configuration from YAML file with validation and defaults.
"""

import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List
import os

logger = logging.getLogger(__name__)

# Default configuration (used if config.yaml is missing or incomplete)
DEFAULT_CONFIG = {
    'network': {
        'interface': 'lo0',
        'queue_size': '1000',
        'bpf_filter': ''
    },
    'detection': {
        'syn_flood': {
            'enabled': True,
            'rate_threshold': 1500,
            'min_packet_count': 15,
            'max_packet_size': 100,
            'severity': 'high'
        },
        'port_scan': {
            'enabled': True,
            'rate_threshold': 500,
            'min_packet_count': 15,
            'max_packet_size': 100,
            'max_flow_duration': 0.5,
            'severity': 'medium'
        },
        'anomaly': {
            'enabled': False,
            'threshold': -0.5,
            'contamination': 0.1
        }
    },
    'flow_tracking': {
        'max_flows': 10000,
        'flow_timeout': 300,
        'cleanup_interval': 60
    },
    'alerting': {
        'log_file': 'ids_alerts.log',
        'min_severity': 'low',
        'deduplication_window': 60,
        'email': {
            'enabled': False,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'from_addresses': '',
            'to_addresses': [],
            'username': '',
            'password': '',
            'severity_threshold': 'high'
        },
        'slack': {
            'enabled': False,
            'webhook_url': '',
            'severity_threshold': 'medium'
        }
    },
    'filtering': {
        'whitelist': ['127.0.0.1', '::1'],
        'blacklist': [],
        'whitelist_ports': []
    },
    'logging': {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'console_enabled': True,
        'file_enabled': True,
        'file_path': 'ids.log'
    },
    'performance': {
        'worker_threads': 0,
        'batch_size': 10,
        'stats_interval': 10
    },
    'advanced': {
        'pcap_capture': {
            'enabled': False,
            'directory': 'captured_traffic',
            'max_size_mb': 100
        },
        'auto_response': {
            'enabled': False,
            'block_threshold': 3,
            'block_duration': 3600
        },
        'database': {
            'enabled': False,
            'type': 'sqlite',
            'path': 'ids_alerts.db',
            'host': 'localhost',
            'username': '',
            'password': '',
            'database': 'ids'
        }
    }
}

class ConfigLoader:
    """
    Loads and manages IDS configuration

    Supports:
    - YAML file loading
    - Default values for missing keys
    - CLI argument overrides
    - Configuration validation
    """

    def __init__(self, config_path: str = "config.yaml"):
        """
        Initialize the config loader.

        Args:
            config_path: Path to the YAML configuration file
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self._validate_config()
        logger.info(f"Configuration loaded from {config_path}")

    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from YAML file with defaults

        Returns:   
            Configuration dictionary
        """
        config = DEFAULT_CONFIG.copy()

        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        config = self._deep_merge(config, user_config)
                        logger.info(f"Loaded configuration from {self.config_path}")
                    else:
                        logger.warning(f"Config file {self.config_path} is empty, using defaults")
            except yaml.YAMLError as e:
                logger.error(f"Error parsing config file: {e}")
                logger.warning("Using default configuration")
            except Exception as e:
                logger.error(f"Error reading config file: {e}")
                logger.warning("Using default configuration")
        else:
            logger.warning(f"Config file {self.config_path} not found, using defaults")
            logger.info("You can create a config.yaml file to customize settings")
        
        return config
    
    def _deep_merge(self, base: Dict, update: Dict) -> Dict:
        """
        Deep merge two dictionaries (update overwrites base).

        Args:
            base: Base dictionary
            update: Dictionary with updates

        Returns:
            Merged dictionary
        """
        result = base.copy()

        for key, value in update.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result
    
    def _validate_config(self):
        """
        Validate configuration values.

        Raises warnings for invalid values and uses defaults.
        """
        # Validate severity levels
        valid_severities = ['low', 'medium', 'high']

        if self.config['detection']['syn_flood']['severity'] not in valid_severities:
            logger.warning(f"Invalid port scan severity, using 'medium'")
            self.config['detection']['port_scan']['severity'] = 'medium'

        # Validate positive integers
        if self.config['network']['queue_size'] <= 0:
            logger.warning("queue_size must be positive, using default (1000)")
            self.config['network']['queue_size'] = 1000

        if self.config['flow_tracking']['max_flows'] <= 0:
            logger.warning("max_flows must be positive, using default (10000)")
            self.config['flow_tracking']['max_flows'] = 10000

        # Validate log level
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.config['logging']['level'] not in valid_levels:
            logger.warning(f"Invalid log level, using 'INFO'")
            self.config['logging']['level'] = 'INFO'

    def get(self, path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-separated path.

        Args:
            path: Dot-separated path (e.g., 'detection.syn_flood.rate_threshold')
            default: Default value if path doesn't exist

        Returns:
            Configuration value or default

        Example:
            config.get('detection.syn_flood.rate_threshold') # Returns 1500
        """
        keys = path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
            
        return value
    
    def override(self, path: str, value: Any):
        """
        Override a configuration value (e.g., from CLI args).

        Args:
            path: Dot-separated path (e.g., 'network.interface)
            value: New value

        Example:
            config.override('network.interface', 'en0')
        """
        keys = path.split('.')
        config = self.config

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value
        logger.info(f"Configuration override: {path} = {value}")

    def get_detection_config(self, rule_name: str) -> Dict[str, Any]:
        """
        Get detection rule configuration.

        Args:
            rule_name Name of the rule ('syn_flood', 'port_scan', etc.)

        Returns:
            Rule configuration dictionary
        """
        return self.config['detection'].get(rule_name, {})
    
    def is_rule_enabled(self, rule_name: str) -> bool:
        """
        Check if a detection rule is enabled.
        
        Args:
            rule_name: Name of the rule
            
        Returns:
            True if enabled, False otherwise
        """
        return self.get(f'detection.{rule_name}.enabled', True)
    
    def get_whitelist(self) -> List[str]:
        """Get list of whitelisted IPs/networks."""
        return self.config['filtering']['whitelist']
    
    def get_blacklist(self) -> List[str]:
        """Get list of blacklisted IPs/networks."""
        return self.config['filtering']['blacklist']
    
    def get_whitelist_ports(self) -> List[int]:
        """Get list of whitelisted ports."""
        return self.config['filtering']['whitelist_ports']
    
    def save_config(self, path: str = None):
        """
        Save current configurations to YAML file.

        Args:
            path: Path to save to (default: original config path)
        """
        save_path = Path(path) if path else self.config_path

        try:
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            logger.info(f"Configuration saved to {save_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    def __str__(self) -> str:
        """ String representation of config. """
        return yaml.dump(self.config, default_flow_style=False)
    


def load_config(config_path: str = "config.yaml", cli_overrides: Dict[str, Any] = None) -> ConfigLoader:
    """
    Convenience function to load configuration.
    
    Args:
        config_path: Path to config file
        cli_overrides: Dictionary of CLI overrides (e.g., {'network.interface': 'en0'})
        
    Returns:
        ConfigLoader instance
        
    Example:
        config = load_config('config.yaml', {'network.interface': 'en0'})
    """
    config = ConfigLoader(config_path)
    
    if cli_overrides:
        for path, value in cli_overrides.items():
            config.override(path, value)
    
    return config