import logging
import json
from datetime import datetime
from collections import defaultdict
from typing import Dict, Tuple, Optional
import time

logger = logging.getLogger(__name__)


class AlertSystem:
    """
    Alert management system with deduplication and rate limiting
    """

    def __init__(self, log_file="ids_alerts.log", config=None):
        """
        Initalize the alert system

        Args:
            log_file: Path to alert log file
            config: ConfigLoader instance (optional)
        """
        self.config = config
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Deduplication settings
        self.deduplication_enabled = self._get_config('alerting.deduplication_window', 60) > 0
        self.deduplication_window = self._get_config('alerting.deduplication_window', 60)

        # Rate limiting settings
        self.rate_limit_enabled = True
        self.rate_limit_per_minute = self._get_config('alerting.rate_limit_per_minute', 100)

        # Alert tracking
        # Key: (src_ip, dst_ip, src_port, dst_port, threat_type)
        # Value: {first_seen, last_alert_time, alert_count, suppressed_count}
        self.alert_history = defaultdict(lambda: {
            'first_seen': None,
            'last_seen': None,
            'last_alert_time': None,
            'alert_count': 0,
            'suppressed_count': 0
        })

        # Rate limiting tracking
        self.recent_alerts = [] # List of timestamps

        # Statistics
        self.stats = {
            'total_alerts_generated': 0,
            'total_alerts_suppressed': 0,
            'total_rate_limited': 0,
            'unique_flows_alerted': 0
        }

        logger.info(f"AlertSystem initialized (deduplication={'enabled' if self.deduplication_enabled else 'disabled'}, "
                    f"window={self.deduplication_window}s, rate_limit={self.rate_limit_per_minute}/min)")

    def _get_config(self, path: str, default):
        """ Get config value or use default """
        if self.config:
            return self.config.get(path, default)
        return default

    def _create_flow_key(self, packet_info: Dict, threat_type: str) -> Tuple:
        """
        Create a unique key for this flow and threat type.

        Args:
            packet_info: Dictionary with packet information
            threat_type: Type of threat detected

        Returns:
            Tuple representing unique flow + threat combination 
        """
        return (
            packet_info.get('source_ip'),
            packet_info.get('destination_ip'),
            packet_info.get('source_port'),
            packet_info.get('destination_port'),
            threat_type
        )

    def _should_suppress_alert(self, flow_key: Tuple, current_time: float) -> bool:
        """
        Check if this alert should be suppressed due to deduplication

        Args:
            flow_key: Unique identifier for this flow + threat
            current_time: Current timestamp

        Returns:    
            True if alert should be suppressed, False otherwise
        """
        if not self.deduplication_enabled:
            return False
        
        history = self.alert_history[flow_key]
        last_alert_time = history['last_alert_time']

        if last_alert_time is None:
            # First alert for this flow - don't suppress
            return False
        
        time_since_last_alert = current_time - last_alert_time

        if time_since_last_alert < self.deduplication_window:
            # Within suppression window - suppress
            return True
        
        # Outside suppression window - allow (ongoing attack update)
        return False

    def _check_rate_limit(self, current_time: float) -> bool:
        """
        Check if we've exceeded the alert rate limit.

        Args:
            current_time: Current timestamp

        Returns:
            True if rate limit exceeded, False otherwise
        """
        if not self.rate_limit_enabled:
            return False
        
        # Clean up old timestamps outside the rate limit window
        cutoff_time = current_time - self.rate_limit_window
        self.recent_alerts = [t for t in self.recent_alerts if t > cutoff_time]

        # Check if we've exceeded the limit
        if len(self.recent_alerts) >= self.rate_limit_per_minute:
            return True
        
        return False
        
    def _update_alert_history(self, flow_key: Tuple, current_time: float, suppressed: bool):
        """
        Update tracking information for this flow.

        Args:
            flow_key: Unique identifier for this flow + threat
            current_time: Current timestamp
            suppressed: Whether this alert was suppressed
        """
        history = self.alert_history[flow_key]

        if history['first_seen'] is None:
            history['first_seen'] = current_time
            self.stats['unique_flows_altered'] += 1

        history['last_seen'] = current_time

        if suppressed:
            history['suppressed_count'] += 1
        else:
            history['last_alert_time'] = current_time
            history['alert_count'] += 1
            self.recent_alerts.append(current_time)

    def generate_alert(self, threat: Dict, packet_info: Dict) -> bool:
        """
        Generate and log an alert for a detected threat.

        Args:
            threat: Dictionary containing threat details (type, confidence, severity, etc.)
            packet_info: Dictionary with packet information (IPs, ports, etc.)

        Returns:
            True if alert was generated, False if suppressed
        """
        current_time = time.time()

        # Get threat type (handle both 'rule' and 'type' formats)
        threat_type = threat.get('rule', threat.get('type', 'unknown'))

        # Create flow key
        flow_key = self._create_flow_key(packet_info, threat_type)

        # Check if it should suppress alert
        suppressed = self._should_suppress_alert(flow_key, current_time)

        # Check rate limit
        rate_limited = False
        if not suppressed:
            rate_limited = self._check_rate_limit(current_time)

        # Update tracking
        self._update_alert_history(flow_key, current_time, suppressed or rate_limited)

        # Update statistics
        if suppressed:
            self.stats['total_alerts_suppressed'] += 1
            logger.debug(f"Alert suppressed for {flow_key} (within {self.deduplication_window}s window)")
            return False
        
        if rate_limited:
            self.stats['total_rate_limited'] += 1
            if self.stats['total_rate_limited'] == 1: # Only log once when rate limiting starts
                logger.warning(f"Rate limit reached ({self.rate_limit_per_minute} alerts/min) - suppressing additional alerts")
            return False
        
        # Generate the alert
        history = self.alert_history[flow_key]

        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat.get('type', 'unknown'),
            'rule': threat_type,
            'severity': threat.get('severity', 'medium'),
            'source_ip': packet_info.get('source_ip'),
            'source_port': packet_info.get('source_port'),
            'destination_ip': packet_info.get('destination_ip'),
            'destination_port': packet_info.get('destination_port'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat,
            # Deduplication metadata
            'first_seen': datetime.fromtimestamp(history['first_seen']).isoformat(),
            'alert_count': history['alert_count'],
            'suppressed_count': history['suppressed_count']
        }

        # Add "ongoing" flag if this is a repeated alert
        if history['alert_count'] > 1:
            alert['status'] = 'ongoing'
            alert['duration_seconds'] = int(current_time - history['first_seen'])
        else:
            alert['status'] = 'new'

        self.logger.warning(json.dumps(alert))

        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat: {threat_type} | "
                f"{packet_info.get('source_ip')}:{packet_info.get('source_port')} -> "
                f"{packet_info.get('destination_ip')}:{packet_info.get('destination_port')} | "
                f"{'NEW' if alert['status'] == 'new' else 'ONGOING (' + str(history['suppressed_count']) + ' suppressed)'}"            
            )

            # TO-DO:
            # - Email notifications
            # - Slack/Discord webhooks?
            # - STEM integration

            self._send_high_priority_notifications(alert)
        
        self.stats['total_alerts_generated'] += 1
        return True

    def _send_high_priority_notifications(self, alert):
        """
        Placeholder for future notifications implementations

        Args:
            alert: Alert dictionary to send
        """ 
        # Placeholder for future email/slack/SIEM notifications
        pass


    def get_statistics(self) -> Dict:
        """
        Get alert system statistics.
        
        Returns:
            Dictionary containing statistics including:
            - total_alerts_generated: Total alerts written to log
            - total_alerts_suppressed: Total alerts suppressed by deduplication
            - total_rate_limited: Total alerts blocked by rate limiting
            - unique_flows_alerted: Number of unique flow+threat combinations
            - suppression_rate: Percentage of alerts suppressed
        """
        total = self.stats['total_alerts_generated'] + self.stats['total_alerts_suppressed']
        suppression_rate = (self.stats['total_alerts_suppressed'] / total * 100) if total > 0 else 0
        
        return {
            **self.stats,
            'suppression_rate': round(suppression_rate, 2),
            'deduplication_enabled': self.deduplication_enabled,
            'deduplication_window': self.deduplication_window,
            'rate_limit_per_minute': self.rate_limit_per_minute,
            'active_flows_tracked': len(self.alert_history)
        }
    

    def get_flow_history(self, limit: int = 10) -> list:
        """
        Get history for the most active flows.
        
        Args:
            limit: Maximum number of flows to return
            
        Returns:
            List of (flow_key, history) tuples, sorted by alert count
        """
        flows = sorted(
            self.alert_history.items(),
            key=lambda x: x[1]['alert_count'] + x[1]['suppressed_count'],
            reverse=True
        )
        return flows[:limit]
    
    def reset_statistics(self):
        """ Reset all statistics and tracking (useful for testing). """
        self.stats = {
            'total_alerts_generated': 0,
            'total_alerts_suppressed': 0,
            'total_rate_limited': 0,
            'unique_flows_alerted': 0
        }
        self.alert_history.clear()
        self.recent_alerts.clear()
        logger.info("Alert system statistics reset")
    
    def cleanup_old_flows(self, max_age_seconds: int = 3600):
        """
        Remove flow history older than specified age.
        
        Args:
            max_age_seconds: Maximum age in seconds (default 1 hour)
        """
        current_time = time.time()
        cutoff_time = current_time - max_age_seconds
        
        keys_to_remove = [
            key for key, history in self.alert_history.items()
            if history['last_seen'] and history['last_seen'] < cutoff_time
        ]
        
        for key in keys_to_remove:
            del self.alert_history[key]
        
        if keys_to_remove:
            logger.info(f"Cleaned up {len(keys_to_remove)} old flow histories")
