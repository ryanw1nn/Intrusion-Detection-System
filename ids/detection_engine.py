"""
Threat detection engine using signature-based and anomaly-based methods.
Implements multiple detection rules and machine learning-based anomaly detection.
"""

from sklearn.ensemble import IsolationForest
import numpy as np
import logging
from typing import Dict, List
from collections import defaultdict
import time

logger = logging.getLogger(__name__)

# TCP Flags
SYN_FLAG = 0x02
ACK_FLAG = 0x10
FIN_FLAG = 0x01
RST_FLAG = 0x04


# Defaults constants (overridden by config if provided)
DEFAULT_ANOMALY_THRESHOLD = -0.5
DEFAULT_SYN_FLOOD_RATE = 1500
DEFAULT_PORT_SCAN_RATE = 500
DEFAULT_MIN_PACKET_COUNT = 15

class DetectionEngine:
    """
    Multi-method threat detection engine.

    Combines signature-based detection (predefined rules for known attack patterns)
    with anomaly-based detection (machine learning to identify unusual behavior).
    """


    def __init__(self, config=None):
        """
        Initialize the detection engine with configuration.
        
        Args:
            config: ConfigLoader instance
        """
        self.config = config

        # Load thresholds from config or use defaults
        self.syn_flood_rate = self._get_config('detection.syn_flood.rate_threshold', DEFAULT_SYN_FLOOD_RATE)
        self.port_scan_rate = self._get_config('detection.port_scan.rate_threshold', DEFAULT_PORT_SCAN_RATE)
        self.min_packet_count = self._get_config('detection.syn_flood.min_packet_count', DEFAULT_MIN_PACKET_COUNT)
        self.anomaly_threshold = self._get_config('detection.anomaly.threshold', DEFAULT_ANOMALY_THRESHOLD)
        self.anomaly_enabled = self._get_config('detection.anomaly.enabled', False)

        # Anomaly detector (machine learning model)
        contamination = self._get_config('detection.anomaly.contamination', 0.1)
        self.anomaly_detector = IsolationForest(
            contamination = contamination,
            random_state = 42
        )

        self.signature_rules = self.load_signature_rules()
        self.is_trained = False

        # Connection tracking for advanced pattern detection
        self.connection_tracker = defaultdict(lambda: {
            'dest_ports': set(),
            'syn_count': 0,
            'last_update': time.time()
        })
        self.tracker_timeout = 60 # clean up tracking data after 60 seconds

        logger.info(f"DetectionEngine initialized with {len(self.signature_rules)} signature rules")
        logger.info(f"Thresholds: SYN flood={self.syn_flood_rate} pkt/s, "
                    f"Port scan={self.port_scan_rate} pkt/s, Min packets={self.min_packet_count}")
        if self.anomaly_enabled:
            logger.info(f"Anomaly detection enabled (threshold={self.anomaly_threshold})")
        else:
            logger.info("Anomaly detection disabled")

    def _get_config(self, path: str, default):
        """ Get config value or use default. """
        if self.config:
            return self.config.get(path, default)
        return default
                    
    def load_signature_rules(self) -> Dict:
        """
        Load signature-based detection rules

        Each rule defines a condition function and metadata about the threat.
        Rules can be enabled/disabled via configuration

        Returns:
            Dictionary mapping rule names to rule definitions
        """
        rules = {}

        # SYN Flood rule
        if self._get_config('detection.syn_flood.enabled', True):
            rules['syn_flood'] = {
                'condition': lambda features: self._detect_syn_flood(features),
                'severity': self._get_config('detection.syn_flood.severity', 'high'),
                'description': 'Potential SYN flood attack detected - high rate of SYN packets'
            }

        # Port Scan Rule    
        if self._get_config('detection.port_scan.enabled', True):
            rules['port_scan'] = {
                'condition': lambda features: self._detect_port_scan(features),
                'severity': self._get_config('detection.port_scan.severity', 'medium'),
                'description': 'Potential port scanning activity detected'
            }

        # Large Packet Rule
        if self._get_config('detection.large_packet.enabled', True):
            size_threshold = self._get_config('detection.large_packet.size_threshold', 1500)
            rules['large_packet'] = {
                'condition': lambda features: features['packet_size'] > size_threshold,
                'severity': self._get_config('detection.large_packet.severity', 'low'),
                'description': 'Unusually large packet detected (exceeds {size_threshold} bytes)'
            }
        
        return rules

    def _detect_syn_flood(self, features: Dict) -> bool:
        """
            Detect SYN flood attacks

            A SYN flood is characterized by:
            - Pure SYN packets (SYN flag set, ACK flag not set)
            - Very high packet rate (sustained attack traffic)
            - Small packet sizes (usually just headers)
            - Multiple packets in the flow

            Args:
                features: Extracted packet features

            Returns:
                True if SYN flood detected, False otherwise
        """
        is_syn = features['tcp_flags'] & SYN_FLAG
        is_ack = features['tcp_flags'] & ACK_FLAG

        # SYN without ACK (not part of normal handshake completion)
        is_pure_syn = is_syn and not is_ack

        # High packet rate and small packets suggest flood
        high_rate = features['packet_rate'] > self.syn_flood_rate

        max_size = self._get_config('detection.syn_flood.max_packet_size', 100)
        small_packet = features['packet_size'] < max_size

        # Require multiple packets to avoid single-packet false positives
        multiple_packets = features.get('packet_count', 1) >= self.min_packet_count

        return is_pure_syn and high_rate and small_packet and multiple_packets

    def _detect_port_scan(self, features: Dict) -> bool:
        """
        Detect port scanning with pattern analysis.
        
        Port scans are characterized by:
        - SYN packets (connection attempts)
        - Small packet sizes
        - High packet rate
        - Short flow durations (quick probes)
        - Multiple packets in the flow

        Args:
            features: Extracted packet features

        Returns:
            True if port scan detected, False otherwise
        """
        is_syn = features['tcp_flags'] & SYN_FLAG
        high_rate = features['packet_rate'] > self.port_scan_rate

        max_size = self._get_config('detection.port_scan.max_packet_size', 100)
        small_packet = features['packet_size'] < max_size

        max_duration = self._get_config('detection.port_scan.max_flow_duration', 0.5)
        short_flow = features['flow_duration'] < max_duration

        # require multiple packets to filter out legitimate single SYN packets
        min_count = self._get_config('detection.port_scan.min_packet_count', self.min_packet_count)
        multiple_packets = features.get('packet_count', 1) >= min_count

        return is_syn and high_rate and small_packet and short_flow and multiple_packets

    def _cleanup_connection_tracker(self):
        """ Remove old entries from connection tracker to prevent memory leaks. """
        current_time = time.time()
        keys_to_remove = [
            k for k, v in self.connection_tracker.items()
            if current_time - v['last_update'] > self.tracker_timeout
        ]
        for key in keys_to_remove:
            del self.connection_tracker[key]

    def train_anomaly_detector(self, normal_traffic_data: np.ndarray):
        """
        Train the anomaly detection model with normal traffic baseline.

        Args:
            normal_traffic_data: NumPy array of shape (n_samples, n_features)
                                 Features: [packet_size, packet_rate, byte_rate]
        """
        try:
            self.anomaly_detector.fit(normal_traffic_data)
            self.is_trained = True
            logger.info(f"Anomaly detector trained with {len(normal_traffic_data)} samples")
        except Exception as e:
            logger.error(f"Failed to train anomaly detector: {e}")
            self.is_trained = False

    def detect_threats(self, features):
        """
        Detect threats using both signature-based and anomaly-bsed detection

        Args:
            features: Dictionary containing extracted packet features:
                    - packet_size: Size of the packet in bytes
                    - packet_rate: Packets per second in this flow
                    - byte_rate: Bytes per second in this flow
                    - tcp_flags: TCP flags as integer
                    - flow_duration: Duration of the flow in seconds
                    - window_size: TCP window size
                    - packet_count: Total packets in flow

        Returns:
            List of threat dictionaries, each containing:
            - type: 'signature' or 'anomaly'
            - rule/score: Rule name for signatures, anomaly score for anomalies
            - confidence: Confdience level (0.0 to 1.0)
            - severity: 'low', 'medium', 'high'
            - description: Human-readable description
        """
        threats = []

        # signature-based detection (always runs)
        for rule_name, rule in self.signature_rules.items():
            try:
                if rule['condition'](features):
                    threats.append({
                        'type': 'signature',
                        'rule': rule_name,
                        'confidence': 1.0,
                        'severity': rule.get('severity', 'medium'),
                        'description': rule.get('description', '')
                    })
            except Exception as e:
                logger.debug(f"Rule '{rule_name}' evaluation failed: {e}")


        # anomaly-based detection (only if trained)
        if self.is_trained:
            try:
                feature_vector = np.array([[
                    features['packet_size'],
                    features['packet_rate'],
                    features['byte_rate']
                ]])

                anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
                
                if anomaly_score < self.anomaly_threshold:
                    # Map anomaly score to severity
                    if anomaly_score < -0.7:
                        severity = 'high'
                    elif anomaly_score < -0.5:
                        severity = 'medium'
                    else:
                        severity = 'low'
                    
                    threats.append({
                        'type': 'anomaly',
                        'score': anomaly_score,
                        'confidence': min(1.0, abs(anomaly_score)),
                        'severity': severity,
                        'description': f'Anomalous traffic pattern detected (score: {anomaly_score:.3f})'
                    })
            except Exception as e:
                logger.error(f"Anomaly detection failed: {e}")
        
        # Periodic cleaning
        if len(self.connection_tracker) > 1000:
            self._cleanup_connection_tracker()

        return threats
    
    def add_signature_rule(self, name: str, condition: callable, severity: str = 'medium',
                           description: str = ''):
        """
        Add a custom signature rule to the detection engine.

        Args:
            name: Unique name for the rule
            condition: Function that takes feature dict and returns bool
            severity: Threat severity ('low', 'medium', 'high')
            description: Human-readable description of the threat
        """
        self.signature_rules[name] = {
            'condition': condition,
            'severity': severity,
            'description': description
        }
        logger.info(f"Added custom signature rule: {name}")

    def remove_signature_rule(self, name: str) -> bool:
        """
        Remove a signature rule from the detection engine.

        Args:  
            name: Name of the rule to remove

        Returns:
            True if rule was removed, false if it didn't exist.
        """
        if name in self.signature_rules:
            del self.signature_rules[name]
            logger.info(f"Removed signature rule: {name}")
            return True
        return False

    def get_statistics(self) -> Dict:
        """
        Get detection engine statistics.

        Returns:
            Dictionary with engine statistics including training status,
            number of rules, and tracked connections
        """
        return {
            'is_trained': self.is_trained,
            'signature_rules_count': len(self.signature_rules),
            'tracked_connections': len(self.connection_tracker),
            'anomaly_threshold': self.anomaly_threshold,
            'available_rules': list(self.signature_rules.keys()),
            'thresholds': {
                'syn_flood_rate': self.syn_flood_rate,
                'port_scan_rate': self.port_scan_rate,
                'min_packet_count': self.min_packet_count
            }
        }

    def reset(self):
        """ Reset the detection engine state (clears connection tracking) """
        num_connections = len(self.connection_tracker)
        self.connection_tracker.clear()
        logger.info(f"Detection engine reset: cleared {num_connections} connection entries")