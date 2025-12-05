"""
Main Intrusion Detection system module.
Integrates packet capture, traffic analysis, threat detection, and alerting.
"""

import logging
import queue
import signal
import sys
from scapy.all import IP, TCP
import argparse

from ids.packet_capture import PacketCapture
from ids.traffic_analyzer import TrafficAnalyzer
from ids.detection_engine import DetectionEngine
from ids.alert_system import AlertSystem
from ids.config_loader import load_config

# Configure logging (will be reconfigured based on config file)
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

    def __init__(self, config=None):
        """
        Initialize the IDS with all required components

        Args:
            config: ConfigLoader instance (optional)
        """
        self.config = config
        self.running = False

        # Get interface from config or use default
        self.interface = self.config.get('network.interface', 'lo0') if self.config else 'lo0'

        # Initialize IDS components with configuration
        logger.info("Initializing IDS components...")

        # Packet Capture
        queue_size = self.config.get('network.queue_size', 1000) if self.config else 1000
        self.packet_capture = PacketCapture(queue_size=queue_size)

        # Traffic Analyzer
        if self.config:
            max_flows = self.config.get('flow_tracking.max_flows', 10000)
            flow_timeout = self.config.get('flow_tracking.flow_timeout', 300)
            self.traffic_analyzer = TrafficAnalyzer(max_flows=max_flows, flow_timeout=flow_timeout)
        else:
            self.traffic_analyzer = TrafficAnalyzer()

        # Detection Engine
        self.detection_engine = DetectionEngine(config=self.config)

        # Alert System
        log_file = self.config.get('alerting.log_file', 'ids_alerts.log') if self.config else 'ids_alerts.log'
        self.alert_system = AlertSystem(log_file=log_file, config=self.config)

        # Statistics 
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'errors': 0
        }

        # Display configuration summary
        if self.config:
            self._display_config_summary()

        logger.info("IDS initialization complete")

    def _display_config_summary(self):
        """Display key configuration settings at startup."""
        logger.info("="*60)
        logger.info("IDS Configuration Summary")
        logger.info("="*60)
        logger.info(f"Interface: {self.interface}")
        logger.info(f"Queue Size: {self.config.get('network.queue_size')}")
        logger.info(f"Max Flows: {self.config.get('flow_tracking.max_flows')}")
        logger.info(f"Flow Timeout: {self.config.get('flow_tracking.flow_timeout')}s")
        logger.info(f"Alert Log: {self.config.get('alerting.log_file')}")
        
        # Detection rules
        logger.info("Enabled Detection Rules:")
        if self.config.get('detection.syn_flood.enabled'):
            logger.info(f"  - SYN Flood (threshold: {self.config.get('detection.syn_flood.rate_threshold')} pkt/s)")
        if self.config.get('detection.port_scan.enabled'):
            logger.info(f"  - Port Scan (threshold: {self.config.get('detection.port_scan.rate_threshold')} pkt/s)")
        if self.config.get('detection.large_packet.enabled'):
            logger.info(f"  - Large Packet (threshold: {self.config.get('detection.large_packet.size_threshold')} bytes)")
        if self.config.get('detection.anomaly.enabled'):
            logger.info(f"  - Anomaly Detection (threshold: {self.config.get('detection.anomaly.threshold')})")
        
        logger.info("="*60)    

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


        if self.config:
            print(f"Configuration: {self.config.config_path}")
            print(f"Alert log: {self.config.get('alerting.log_file')}")
        else:
            print(f"Alert log: ids_alerts.log")
            print(f"(No config file - using defaults)")

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
    
def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System with Configuration Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Use default config.yaml
  sudo python3 -m ids.intrusion_detection_system
  
  # Use custom config file
  sudo python3 -m ids.intrusion_detection_system -c my_config.yaml
  
  # Override interface via CLI
  sudo python3 -m ids.intrusion_detection_system -i en0
  
  # Override multiple settings
  sudo python3 -m ids.intrusion_detection_system -i eth0 --syn-flood-threshold 2000

Configuration File:
  The IDS looks for config.yaml in the current directory by default.
  You can specify a different file with the -c/--config option.
  CLI arguments override config file settings.
        """
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to monitor (overrides config file)'
    )
    
    parser.add_argument(
        '--syn-flood-threshold',
        type=int,
        help='SYN flood detection threshold in packets/sec (overrides config)'
    )
    
    parser.add_argument(
        '--port-scan-threshold',
        type=int,
        help='Port scan detection threshold in packets/sec (overrides config)'
    )
    
    parser.add_argument(
        '--min-packets',
        type=int,
        help='Minimum packet count for detection (overrides config)'
    )
    
    parser.add_argument(
        '--no-config',
        action='store_true',
        help='Run without loading config file (use all defaults)'
    )

    return parser.parse_args()

def main():
    """
    Main entry point for running the IDS as a standalone application.
    
    Phase 2, Item #5: Enhanced with configuration file support.
    """
    args = parse_arguments()
    
    try:
        # Load configuration (unless --no-config specified)
        if args.no_config:
            logger.info("Running without config file (--no-config specified)")
            config = None
        else:
            # Build CLI overrides dictionary
            cli_overrides = {}
            
            if args.interface:
                cli_overrides['network.interface'] = args.interface
            
            if args.syn_flood_threshold:
                cli_overrides['detection.syn_flood.rate_threshold'] = args.syn_flood_threshold
            
            if args.port_scan_threshold:
                cli_overrides['detection.port_scan.rate_threshold'] = args.port_scan_threshold
            
            if args.min_packets:
                cli_overrides['detection.syn_flood.min_packet_count'] = args.min_packets
                cli_overrides['detection.port_scan.min_packet_count'] = args.min_packets
            
            # Load config with overrides
            config = load_config(args.config, cli_overrides)
        
        # Create and start IDS
        ids = IntrusionDetectionSystem(config=config)
        ids.start()
        
    except PermissionError:
        print("\nERROR: Permission denied. Try running with sudo:")
        print(f"    sudo python3 -m ids.intrusion_detection_system -i {args.interface if args.interface else 'lo0'}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"\nERROR: Configuration file not found: {args.config}")
        print("Create a config.yaml file or use --no-config to run with defaults")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)