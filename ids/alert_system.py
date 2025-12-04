import logging
logger = logging.getLogger(__name__)
import json
from datetime import datetime


class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        """
        Generate and log an alert for a detected threat.

        Args:
            threat: Dictionary containing threat details (type, confidence, severity, etc.)
            packet_info: Dictionary with packet information (IPs, ports, etc.)
        """

        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )
            self._send_high_priority_notifications(alert)

    def _send_high_priority_notifications(self, alert):
        """
        Placeholder for future notifications implementations

        Args:
            alert: Alert dictionary to send
        """ 
        # Placeholder for future email/slack/SIEM notifications
        pass
