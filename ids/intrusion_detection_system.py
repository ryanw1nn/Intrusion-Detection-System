"""
Main Intrusion Detection system module.
Integrates packet capture, traffic analysis, threat detection, and alerting.
"""

import logging
import queue
import signal
import sys
from scapy.all import IP, TCP

from ids.packet_capture import PacketCapture
from ids.traffic_analyzer import TrafficAnalyzer
from ids.detection_engine import DetectionEngine
from ids.alert_system import AlertSystem

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IntrusionDetectionSystem:
    """
    Network Intrusion Detection System (IDS).

    Captures network packets, analyzes traffic patterns, detects threats using
    signature-based and anomaly-based methods, and generate alerts.
    """

    def __init__(self, interface="lo0"):
        """
        Initialize the IDS with all required components

        Args:
            interface: Network interface to monitor (e.g., 'eth0, 'en0', 'lo0')
        """
        self.interface = interface
        self.running = False

        # Initialize IDS components
        logger.info("Initializing IDS components...")
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        # Statistics 
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'errors': 0
        }        

        logger.info("IDS initialization complete")

    def start(self):
        """
        Start the IDS and begin monitoring network traffic.
        Runs until interrupted (Ctrl+C) or stopped programmatically
        """
        self.running = True

        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info(f"Starting IDS on interface: {self.interface}")
        print(f"{'='*60}")
        print(f"Network IDS Started")
        print(f"{'='*60}")
        print(f"Monitoring interface: {self.interface}")
        print(f"Alert log: ids_alerts.log")
        print(f"Press Ctrl+C to stop")
        print(f"{'='*60}\n")

        # Start packet capture
        self.packet_capture.start_capture(self.interface)

        # Main processing loop
        while self.running:
            try:
                # Get packet from queue with timeout
                packet = self.packet_capture.packet_queue.get(timeout=1)
                self._process_packet(packet)

            except queue.Empty:
                # Normal timeout- no packets available
                continue 

            except KeyboardInterrupt:
                # Should be caught by signal handler
                logger.info("Received keyboard interrupt")
                self.stop()
                break

            except Exception as e:
                logger.error(f"Error processing packet: {e}", exc_info=True)
                self.stats['errors'] += 1
                continue
            
        logger.info("IDS main loop terminated")

    def _process_packet(self, packet):
        """
        Process a single packet through the IDS pipline.

        Args:
            packet: Scapy packet object
        """
        # Extract features from packet
        features = self.traffic_analyzer.analyze_packet(packet)

        if not features:
            return
        
        self.stats['packets_processed'] += 1

        # Detect threats
        threats = self.detection_engine.detect_threats(features)

        if threats:
            self.stats['threats_detected'] += len(threats)

            # Generate alerts for each detected threat
            for threat in threats:
                packet_info = {
                    'source_ip': packet[IP].src,
                    'source_port': packet[TCP].sport,
                    'destination_ip': packet[IP].dst,
                    'destination_port': packet[TCP].dport
                }
                self.alert_system.generate_alert(threat, packet_info)

            # log to console for visibility
            logger.warning(
                f"THREAT: {threat.get('rule', threat['type'])} | "
                f"{packet[IP].src}:{packet[TCP].sport} -> "
                f"{packet[IP].dst}:{packet[TCP].dport}"
            )

    def _signal_handler(self, signum, frame):
        """
        Handle interrupt signals for graceful shutdown.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        logger.info(f"Received signal {signum}")
        print("\n\nShutting down gracefully...")
        self.stop()

    def stop(self):
        """
        Stop the IDS and clean up resources
        Displays final statistics before exiting
        """
        if not self.running:
            return
        
        self.running = False
        logger.info("Stopping IDS...")

        # Stop packet capture
        self.packet_capture.stop()

        # Display statistics
        print(f"\n{'='*60}")
        print(f"IDS Statistics")
        print(f"{'='*60}")
        print(f"Packets processed: {self.stats['packets_processed']}")
        print(f"Threats detected: {self.stats['threats_detected']}")
        print(f"Errors encountered: {self.stats['errors']}")
        print(f"{'='*60}\n")
        
        logger.info("IDS stopped successfully")

    def get_statistics(self):
        """
        Get current IDS statistics.

        Returns:
            Dictionary containing IDS statistics
        """
        return {
            **self.stats,
            'active_flows': self.traffic_analyzer.get_flow_count(),
            'queue_size': self.packet_capture.get_queue_size(),
            'detection_engine': self.detection_engine.get_statistics()
        }
    
def main():
    """
    Main entry point for running the IDS as a standalone application.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    parser.add_argument(
        '-i', '--interface',
        default='lo0',
        help='Network intreface to monitor (default: lo0)'
    )

    args = parser.parse_args()

    try:
        ids = IntrusionDetectionSystem(interface=args.interface)
        ids.start()
    except PermissionError:
        print("\nERROR: Permission denied. Try running with sudo:")
        print(f"    sudo python3 -m ids.intrusion_detection_system -i {args.interface}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()