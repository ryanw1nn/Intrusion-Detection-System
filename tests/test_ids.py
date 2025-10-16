from scapy.all import IP, TCP
from ids.intrusion_detection_system import IntrusionDetectionSystem
import numpy as np



def test_ids():
    # create test packets to simulate various scenarios
    test_packets = [
        # normal traffic
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),

        # SYN flood simulation
        IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="192.168.1.2") / TCP(sport=5679, dport=80, flags="S"),
        IP(src="10.0.0.3", dst="192.168.1.2") / TCP(sport=5680, dport=80, flags="S"),

        # port scan simulation
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),
    ]

    ids = IntrusionDetectionSystem()

    # simulate packet processing and threat detection
    print("Starting IDS Test...")
    for i, packet in enumerate(test_packets, 1):
        print(f"\nProcessing packet {i}: {packet.summary()}")

        # analyze the packet
        features = ids.traffic_analyzer.analyze_packet(packet)

        normal_data = np.array([
            [100, 10, 1000],  # packet_size, packet_rate, byte_rate
            [120, 15, 1500],
            [80, 5, 800]
        ])

        ids.detection_engine.train_anomaly_detector(normal_data)

        if features:
            # detect threats based on features
            threats = ids.detection_engine.detect_threats(features)

            if threats:
                print(f"Detected threats: {threats}")
            else: 
                print("No threats detected.")
        else:
            print("Packet does not contain IP/TCP layers or is ignored.")
        
    print("\nIDS Test Completed.")

if __name__ == "__main__":
    test_ids()