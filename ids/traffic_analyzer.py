from scapy.all import IP, TCP
from collections import OrderedDict
from typing import Dict, Optional, Tuple
import time
import logging
logger = logging.getLogger(__name__)

MIN_TIME_DIFF = 1e-6
DEFAULT_MAX_FLOWS = 10000
DEFAULT_FLOW_TIMEOUT = 300 # 5 minutes

class TrafficAnalyzer:

    def __init__(self, max_flows: int = DEFAULT_MAX_FLOWS, flow_timeout: int = DEFAULT_FLOW_TIMEOUT):
        """
            Initialize the Traffic Analyzer.

            Args:
                max_flows: Maximum number of flows to track simultaneously
                flow_timeout: Time in secodns after which inactive flows are cleaned up
        """

        self.flow_stats = OrderedDict()
        self.max_flows = max_flows
        self.flow_timeout = flow_timeout
        self.last_cleanup_time = time.time()
        self.cleanup_interval = 60 # runs cleanup every 60 seconds
        
    
    def analyze_packet(self, packet) -> Optional[Dict[str, float]]:
        """
            Analyze a packet and extract flow features.

            Args:
                packet: Scapy packet object

            Returns: 
                Dictionary of extracted features or None if packet is invalid
        """

        if IP not in packet or TCP not in packet:
            return None
            
        try:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst, 'TCP')

            # update flow statistics
            stats = self._get_or_create_flow_stats(flow_key)
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = getattr(packet, 'time', time.time())

            if stats['start_time'] is None:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            # periodic cleanup of old flows
            self._periodic_cleanup()

            return self.extract_features(packet, stats)
        
        except Exception as e:
            logger.error(f"Error analyzng packet: {e}")
            return None
        

    def _get_or_create_flow_stats(self, flow_key: Tuple) -> Dict:
        """
        Get existing flow stats or create new entry.

        Args:
            flow_key: Tuple identifying the flow

        Returns:
            Dictionary containing flow statistics
        """
        if flow_key not in self.flow_stats:
            # if at max capacity, remove oldest flow
            if len(self.flow_stats) >= self.max_flows:
                self.flow_stats.popitem(last=False)
                logger.debug(f"Removed oldest flow. Current flows: {len(self.flow_stats)}")

            self.flow_stats[flow_key] = {
                'packet_count': 0,
                'byte_count': 0,
                'start_time': None,
                'last_time': None
            }
        else:
            # move to end (most recently used)
            self.flow_stats.move_to_end(flow_key)
        
        return self.flow_stats[flow_key]


    def _periodic_cleanup(self) -> None:
        """
        Periodically clea up old inactive flows.
        """
        current_time = time.time()
        
        # only run cleanup at specified intervals
        if current_time - self.last_cleanup_time < self.cleanup_interval:
            return
        
        self.cleanup_old_flows()
        self.last_cleanup_time = current_time

    
    def cleanup_old_flows(self) -> int:
        """"
        Remove flows that have been inactive for longer than flow_timeout

        Returns: Number of flows removed
        """
        current_time = time.time()
        keys_to_remove = []

        for flow_key, stats in self.flow_stats.items():
            if stats['last_time'] and current_time - stats['last_time'] > self.flow_timeout:
                keys_to_remove.append(flow_key)

        for key in keys_to_remove:
            del self.flow_stats[key]
            
        if keys_to_remove:
            logger.info(f"Cleaned up {len(keys_to_remove)} inactive flows. Active flows: {len(self.flow_stats)}")

        return len(keys_to_remove)
    

    def extract_features(self, packet, stats):
        """
        Extract features from packet and flow statistics.

        Args:
            packet: Scapy packet object
            stats: Flow statistics dictionary

        Returns:
            Dictionary of extracted features
        """
        time_diff = stats['last_time'] - stats['start_time']

        # prevent division by zero for single-packet flows
        if time_diff <= 0:
            time_diff = MIN_TIME_DIFF

        return {
            'packet_size': len(packet),
            'flow_duration': time_diff,
            'packet_rate': stats['packet_count'] / time_diff,
            'byte_rate': stats['byte_count'] / time_diff,
            'tcp_flags': int(packet[TCP].flags),
            'window_size': packet[TCP].window,
            'packet_count': stats['packet_count']
        }
    
    def get_flow_count(self) -> int:
        """
        Get the number of tracked flows.

        Returns:
            Number of active flows
        """
        return len(self.flow_stats)
    
    def reset(self) -> None:
        """
        Clear all flow statistics. For testing or restarting analysis
        """
        self.flow_stats.clear()
        logger.info("All flow statistics reset")