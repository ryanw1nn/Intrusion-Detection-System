from sklearn.ensemble import IsolationForest
import numpy as np
import logging
logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.is_trained = False

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and # SYN flag
                    features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features, flow_key: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50 and
                    self._is_scanning_pattern(flow_key) # track unique dest ports
                )
            }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)

    def detect_threats(self, features):
        
        ANOMALY_THRESHOLD = -0.5

        if not self.is_trained:
            # skip anomaly detection or use fit_predict strategy
            return self._signature_only_detection(features)


        threats = []

        # signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })
        # anomaly-based detection

        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]])

        anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
        if anomaly_score < ANOMALY_THRESHOLD:
            threats.append({
                'type': 'anomaly',
                'score': anomaly_score,
                'confidence': min(1.0, abs(anomaly_score))
            })
        
        return threats