import logging
logger = logging.getLogger(__name__)
from scapy.all import IP, TCP
import queue
from ids.packet_capture import PacketCapture
from ids.traffic_analyzer import TrafficAnalyzer
from ids.detection_engine import DetectionEngine
from ids.alert_system import AlertSystem


class IntrusionDetectionSystem:
    def __init__(self, interface="lo0"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        
        self.interface = interface

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features)

                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }
                        self.alert_system.generate_alert(threat, packet_info)
            except queue.Empty:
                continue

            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.packet_capture.stop()
                break
            
            except Exception as e:
                logging.error(f"Packet processing error: {e}")
                continue

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()