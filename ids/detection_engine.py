from sklearn.ensemble import IsolationForest
import numpy as np
import logging
from typing import Dict, List
from collections import defaultdict
import time

logger = logging.getLogger(__name__)

ANOMALY_THRESHOLD = -0.5
SYN_FLAG = 0x02
ACK_FLAG = 0x10
FIN_FLAG = 0x01
RST_FLAG = 0x04

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.is_trained = False

        # Track connection patterns for more sophisticated detection
        self.connection_tracker = defaultdict(lambda: {
            'dest_ports': set(),
            'syn_count': 0,
            'last_update': time.time()
        })
        self.tracker_timeout = 60 # clean up tracking data after 60 seconds

    def load_signature_rules(self):
        """
        Load signature-based detection rules
        Returns a dictionary of rule name -> rule definition
        """
        return {
            'syn_flood': {
                'condition': lambda features: self._detect_syn_flood(features),
                'severity': 'high',
                'description': 'Potential SYN flood attack detected'
            },
            'port_scan': {
                'condition': lambda features: self._detect_port_scan(features),
                'severity': 'medium',
                'description': 'Potential port scanning activity detected'
            },
            'large_packet': {
                'condition': lambda features: (
                    features['packet_size'] > 1500 # larger than typical MTU
                ),
                'severity': 'low',
                'description': 'Unusually large packet detected'
            }
  #          'connection_flood': {
   #             'condition': lambda features: (
    #                features['packet_rate'] > 200 # very high connection rate
     #           ),
      #          'severity': 'high',
       #         'description': 'Potential connection flood attack'
        #    }
        }

    def _detect_syn_flood(self, features: Dict) -> bool:
        """
            Detect SYN flood attacks

            A SYN flood is characterized by:
            - High rate of SYN packets
            - Small packet sizes (usually just headers)
            - No corresponding ACK packets in the flow
        """
        is_syn = features['tcp_flags'] & SYN_FLAG
        is_ack = features['tcp_flags'] & ACK_FLAG

        # SYN without ACK (not part of normal handshake completion)
        is_pure_syn = is_syn and not is_ack

        # High packet rate and small packets suggest flood
        high_rate = features['packet_rate'] > 100
        small_packet = features['packet_size'] < 100

        # For single-packet flows with extreme rates, still detect
        extreme_rate = features['packet_rate'] > 10000
        single_packet = features.get('packet_count, 1') == 1

        # Trigger on either multi-packet flows OR extreme single-packet rates
        if single_packet and extreme_rate:
            return is_pure_syn and small_packet
        else:
            sufficient_packets = features.get('packet_count', 1) > 5
            return is_pure_syn and high_rate and small_packet and sufficient_packets

    def _detect_port_scan(self, features: Dict) -> bool:
        """
        Detect port scanning with pattern analysis.
        
        Port scans are characterized by:
        - SYN packets to many different ports
        - Small packet sizes
        - High packet rate
        - Short flow durations
        """
        is_syn = features['tcp_flags'] & SYN_FLAG
        high_rate = features['packet_rate'] > 20 # Lower threshold than SYN flood
        small_packet = features['packet_size'] < 100
        short_flow = features['flow_duration'] < 2.0 # quick probes

        # for single-packet flows with extreme rates
        extreme_rate = features['packet_rate'] > 10000\
        single_packet = features.get('packet_count', 1) == 1

        if single_packet and extreme_rate:
            return is_syn and small_packet and short_flow
        else:
            sufficient_packets = features.get('packet_count', 1) > 5
            return is_syn and high_rate and small_packet and sufficient_packets


        # Must all all characteristics to reduce false positives
        return is_syn and high_rate and small_packet and short_flow and sufficient_packets
        
    def _cleanup_connection_tracker(self):
        """ Remove old entries from connection tracker """
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
                                 where features are [packet_size, packet_rate, byte_rate]
        """
        try:
            self.anomaly_detector.fit(normal_traffic_data)
            self.is_trained = True
            logger.info(f"Anomaly detector trained with {len(normal_traffic_data)} samples")
        except Exception as e:
            logger.error(f"Failed to train anomaly detector: {e}")
            self.is_trained = False

    def _signature_only_detection(self, features):
        """
        Run only signature-based detection (when ML model is not trained).

        Args:
            features: Dictionary of packet features

        Returns:
            List of detected threats
        """
        threats=[]

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
                
        return threats


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
                logger.debug(f"Rule '{rule.name}' evaluation failed: {e}")


        # anomaly-based detection (only if trained)
        if self.is_trained:
            try:
                feature_vector = np.array([[
                    features['packet_size'],
                    features['packet_rate'],
                    features['byte_rate']
                ]])

                anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
                
                if anomaly_score < ANOMALY_THRESHOLD:
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
    
    def get_statistics(self) -> Dict:
        """
        Get detection engine statistics.

        Returns:
            Dictionary with engine statistics
        """
        return {
            'is_trained': self.is_trained,
            'signature_rules_count': len(self.signature_rules),
            'tracked_connections': len(self.connection_tracker),
            'anomaly_threshold': ANOMALY_THRESHOLD
        }

    def reset(self):
        """ Reset the detection engine state """
        self.connection_tracker.clear()
        self.is_trained = False
        logger.info("Detection engine reset")