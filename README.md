# Network Intrusion Detection System (IDS)

A production-ready Python-based Network Intrusion Detection System that monitors network traffic in real-time to detect security threats using both signature-based and anomaly-based detection methods.

## 🎯 Features

- **Real-time Packet Capture**: Monitors network interfaces for TCP/IP traffic using Scapy
- **Dual Detection Methods**:
  - **Signature-based**: Detects known attack patterns (SYN floods, port scans, large packets)
  - **Anomaly-based**: Uses machine learning (Isolation Forest) to identify unusual traffic patterns
- **Flow Tracking**: Maintains detailed statistics for individual network flows with LRU eviction
- **Structured Alerting**: Logs threats to file in JSON format with severity levels
- **Comprehensive Testing**: Full unit test suite with live network and PCAP testing capabilities
- **Extensible Architecture**: Easily add custom detection rules and notification methods
- **Performance Optimized**: Handles high-traffic networks with configurable queue sizes and flow limits

## 📋 Table of Contents

- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Detection Methods](#detection-methods)
- [Testing](#testing)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Performance & Tuning](#performance--tuning)


- [Future Enhancements](#future-enhancements)

## 🏗️ Architecture

```
┌──────────────────┐
│ Packet Capture   │ ──> Captures TCP/IP packets from network interface
│  (Scapy + Queue) │     • Threaded capture to prevent blocking
└────────┬─────────┘     • Configurable queue size (default: 1000)
         │
         ▼
┌──────────────────┐
│Traffic Analyzer  │ ──> Extracts features and tracks flow statistics
│  (Flow Tracking) │     • 5-tuple flow identification
└────────┬─────────┘     • LRU eviction policy
         │               • Automatic cleanup of old flows
         ▼
┌──────────────────┐
│Detection Engine  │ ──> Applies detection rules and ML models
│ (Signatures + ML)│     • Signature rules with tunable thresholds
└────────┬─────────┘     • Isolation Forest anomaly detection
         │               • Extensible rule framework
         ▼
┌──────────────────┐
│  Alert System    │ ──> Logs and notifies about detected threats
│ (JSON Logging)   │     • Structured JSON alert format
└──────────────────┘     • Severity-based filtering
                         • Hooks for custom notifications
```

## 🚀 Installation

### Prerequisites

- **Python**: 3.8 or higher
- **OS**: Linux, macOS, or Windows with WSL
- **Permissions**: Root/sudo access (required for packet capture)

### Setup Steps

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd IDS_project
   ```

2. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Dependencies

Create a `requirements.txt` file with:
```
scapy>=2.5.0
scikit-learn>=1.3.0
numpy>=1.24.0
```

## ⚡ Quick Start

```bash
# 1. Activate virtual environment
source venv/bin/activate

# 2. Run unit tests to verify installation
python -m tests.test_ids

# 3. Test with synthetic attack traffic
python -m tests.test_ids --pcap

# 4. Start the IDS (requires sudo)
sudo python3 -m ids.intrusion_detection_system -i en0

# 5. View alerts in real-time (in another terminal)
tail -f ids_alerts.log
```

## 📖 Usage

### Finding Your Network Interface

**macOS/BSD**:
```bash
ifconfig
```

**Linux**:
```bash
ip link show
# or
ifconfig
```

Common interface names:
| Interface | Description |
|-----------|-------------|
| `lo0` / `lo` | Loopback (local traffic only) |
| `eth0` | Ethernet (Linux) |
| `en0` / `en1` | WiFi/Ethernet (macOS) |
| `wlan0` | WiFi (Linux) |

### Running the IDS

**Monitor specific interface**:
```bash
sudo python3 -m ids.intrusion_detection_system -i en0
```

**Default behavior** (monitors `lo0`):
```bash
sudo python3 -m ids.intrusion_detection_system
```

### Stopping the IDS

Press `Ctrl+C` for graceful shutdown. The system will:
- Stop packet capture
- Flush remaining packets
- Display statistics
- Clean up resources

### Viewing Alerts

**Real-time monitoring**:
```bash
tail -f ids_alerts.log
```

**Pretty-print JSON alerts**:
```bash
cat ids_alerts.log | python -m json.tool
```

**Filter by severity**:
```bash
grep '"severity": "high"' ids_alerts.log
```

### Example Alert

```json
{
  "timestamp": "2025-10-27T14:30:45.123456",
  "threat_type": "signature",
  "rule": "port_scan",
  "severity": "medium",
  "confidence": 1.0,
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "destination_ip": "192.168.1.2",
  "destination_port": 80,
  "description": "Potential port scanning activity detected"
}
```

## 🔍 Detection Methods

### Signature-Based Detection

Detects known attack patterns using predefined rules:

#### 1. **SYN Flood Attack**
- **Indicators**:
  - Pure SYN packets (no ACK flag)
  - Very high packet rate (>500 packets/second)
  - Small packet sizes (<100 bytes)
  - Multiple packets in flow (≥3)
- **Severity**: High
- **Common scenarios**: DDoS attacks, resource exhaustion

#### 2. **Port Scan**
- **Indicators**:
  - SYN packets to multiple ports
  - High packet rate (>100 packets/second)
  - Small packet sizes (<100 bytes)
  - Very short flow duration (<0.5 seconds)
  - Multiple packets in flow (≥3)
- **Severity**: Medium
- **Common scenarios**: Network reconnaissance, vulnerability scanning

#### 3. **Large Packet**
- **Indicators**:
  - Packet size exceeds typical MTU (>1500 bytes)
- **Severity**: Low
- **Common scenarios**: Potential fragmentation attacks, data exfiltration

### Anomaly-Based Detection

Uses **Isolation Forest** machine learning algorithm:
- **Training**: Learns baseline from normal traffic patterns
- **Detection**: Identifies statistical outliers in real-time
- **Features**: Packet size, packet rate, byte rate
- **Threshold**: Configurable (default: -0.5)
- **Note**: Requires training data; disabled by default in live tests to avoid false positives

## 🧪 Testing

### Unit Tests

Run the complete test suite:
```bash
python -m tests.test_ids
```

Tests include:
- ✅ Packet analysis and feature extraction
- ✅ Flow tracking and cleanup
- ✅ SYN flood detection
- ✅ Port scan detection
- ✅ Normal traffic (no false positives)
- ✅ Anomaly detection

### PCAP File Testing

Test with synthetic attack traffic:
```bash
python -m tests.test_ids --pcap
```

This generates a PCAP file containing:
- 20 normal packets (ACK flags)
- 50 SYN flood packets (from different sources)
- 80 port scan packets (to sequential ports)

### Live Network Testing

Test on real network traffic:
```bash
sudo python3 -m tests.test_ids --live en0
```

**Note**: Anomaly detection is disabled for live tests to prevent false positives from poorly matched synthetic training data.

### Test with Custom PCAP

```bash
python -m tests.test_ids --pcap /path/to/your/capture.pcap
```

## ⚙️ Configuration

### Adding Custom Detection Rules

```python
from ids.detection_engine import DetectionEngine

engine = DetectionEngine()

# Define custom rule
def detect_large_outbound(features):
    return (
        features['byte_rate'] > 1000000 and  # >1MB/sec
        features['flow_duration'] > 10
    )

# Add to engine
engine.add_signature_rule(
    name='large_outbound',
    condition=detect_large_outbound,
    severity='high',
    description='Large sustained outbound transfer detected'
)
```

### Adjusting Detection Thresholds

Edit `ids/detection_engine.py`:

```python
# SYN Flood threshold
very_high_rate = features['packet_rate'] > 500  # Adjust this value

# Port Scan threshold
high_rate = features['packet_rate'] > 100  # Adjust this value
```

### Customizing System Parameters

```python
from ids.intrusion_detection_system import IntrusionDetectionSystem
from ids.traffic_analyzer import TrafficAnalyzer
from ids.packet_capture import PacketCapture

# Create IDS with custom configuration
ids = IntrusionDetectionSystem(interface='en0')

# Customize traffic analyzer
ids.traffic_analyzer = TrafficAnalyzer(
    max_flows=5000,      # Track up to 5000 concurrent flows
    flow_timeout=600     # Keep flows for 10 minutes
)

# Customize packet capture
ids.packet_capture = PacketCapture(
    queue_size=2000      # Buffer up to 2000 packets
)

ids.start()
```

## 📁 Project Structure

```
IDS_project/
├── ids/                              # Main IDS package
│   ├── __init__.py
│   ├── intrusion_detection_system.py  # Main orchestration & CLI
│   ├── packet_capture.py              # Network packet capture
│   ├── traffic_analyzer.py            # Flow tracking & feature extraction
│   ├── detection_engine.py            # Threat detection logic
│   └── alert_system.py                # Alert logging & notifications
│
├── tests/                            # Test suite
│   └── test_ids.py                   # Unit & integration tests
│
├── requirements.txt                  # Python dependencies
├── README.md                         # This file
├── ids_alerts.log                    # Generated alert log (JSON)
└── test_traffic.pcap                 # Generated test PCAP (optional)
```

## 📊 Performance & Tuning

### Typical Resource Usage

- **CPU**: 5-15% on moderate traffic (1000 packets/sec)
- **Memory**: ~100MB baseline + ~1KB per tracked flow
- **Disk I/O**: Minimal (alert logging only)

### Performance Tuning

#### High-Traffic Networks
```python
# Increase queue size and flow limits
PacketCapture(queue_size=5000)
TrafficAnalyzer(max_flows=50000, flow_timeout=60)
```

#### Low-Resource Systems
```python
# Reduce memory footprint
TrafficAnalyzer(max_flows=1000, flow_timeout=120)
PacketCapture(queue_size=500)
```

#### Busy Networks with Many Short Connections
```python
# Shorter timeout for faster cleanup
TrafficAnalyzer(flow_timeout=60, cleanup_interval=30)
```

### Flow Management

- **LRU Eviction**: Oldest flows removed when max_flows reached
- **Timeout Cleanup**: Inactive flows cleaned up every 60 seconds
- **Manual Cleanup**: `traffic_analyzer.cleanup_old_flows()`

## 🔧 Troubleshooting

### Permission Denied

**Problem**: `PermissionError` when starting IDS

**Solution**:
```bash
sudo python3 -m ids.intrusion_detection_system -i en0
```

Packet capture requires root privileges to access raw sockets.

---

### No Packets Captured

**Symptoms**: IDS starts but shows 0 threats and 0 packets processed

**Solutions**:
1. **Verify interface exists and is up**:
   ```bash
   ifconfig  # Should show interface with UP status
   ```

2. **Check for traffic on interface**:
   ```bash
   sudo tcpdump -i en0 -c 10  # Should show packets
   ```

3. **Try loopback interface**:
   ```bash
   sudo python3 -m ids.intrusion_detection_system -i lo0
   # Generate traffic: curl http://localhost:8000
   ```

---

### High False Positive Rate

**Symptoms**: Normal HTTPS traffic triggering SYN flood/port scan alerts

**Solutions**:

1. **Increase detection thresholds** in `detection_engine.py`:
   ```python
   # SYN Flood
   very_high_rate = features['packet_rate'] > 1000  # Increase from 500
   
   # Port Scan
   high_rate = features['packet_rate'] > 200  # Increase from 100
   ```

2. **Disable anomaly detection** for production use (only use signatures)

3. **Add whitelisting** for trusted sources

---

### Memory Usage Growing

**Symptoms**: IDS memory usage increases over time

**Solutions**:

1. **Reduce max_flows**:
   ```python
   TrafficAnalyzer(max_flows=5000)  # Down from 10000
   ```

2. **Decrease flow_timeout**:
   ```python
   TrafficAnalyzer(flow_timeout=180)  # 3 minutes instead of 5
   ```

3. **Manual cleanup**:
   ```python
   ids.traffic_analyzer.cleanup_old_flows()
   ```

---

### Packet Queue Full

**Symptoms**: Log shows "Packet queue full - dropping packet"

**Solutions**:

1. **Increase queue size**:
   ```python
   PacketCapture(queue_size=5000)
   ```

2. **Optimize detection logic** to process packets faster

3. **Use faster hardware** or reduce traffic with BPF filters

## 🚧 Limitations

Current limitations and known issues:

- **TCP Only**: Only monitors TCP traffic (UDP/ICMP not supported)
- **Single Interface**: Monitors one network interface at a time
- **No Payload Inspection**: Only analyzes packet headers and statistics
- **IPv4 Focused**: Limited IPv6 support
- **Real-time Only**: Production mode doesn't support offline PCAP analysis
- **No Packet Reassembly**: Fragmented packets treated as separate flows
- **Local Analysis**: No distributed deployment or correlation

## 🔮 Future Enhancements

Planned features and improvements:

- [ ] **Protocol Support**
  - UDP traffic analysis
  - ICMP monitoring
  - Full IPv6 support

- [ ] **Advanced Detection**
  - Deep packet inspection (DPI)
  - Payload pattern matching
  - Behavioral analysis (connection patterns)
  - Geo-IP analysis

- [ ] **User Interface**
  - Web-based dashboard (Flask/FastAPI)
  - Real-time visualization
  - Historical analysis

- [ ] **Notifications**
  - Email alerts
  - Slack integration
  - Webhook support
  - SIEM forwarding (Splunk, ELK)

- [ ] **Configuration**
  - YAML/JSON rule definitions
  - Hot-reload configuration
  - Per-interface settings

- [ ] **Deployment**
  - Docker containerization
  - Distributed deployment
  - Multi-interface support
  - Cloud integration (AWS, Azure)

- [ ] **Performance**
  - Multi-threaded packet processing
  - Hardware acceleration
  - BPF filtering

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Add tests** for new features
4. **Ensure all tests pass**: `python -m tests.test_ids`
5. **Follow code style**: PEP 8 compliance
6. **Update documentation**: README and docstrings
7. **Submit pull request** with detailed description

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/IDS_project.git
cd IDS_project

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install -r requirements.txt
pip install pytest black flake8  # Additional dev tools

# Run tests
python -m tests.test_ids

# Run linter
flake8 ids/ tests/
```


## 👨‍💻 Authors

**Ryan Winn**

## 🙏 Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **scikit-learn**: Machine learning framework for anomaly detection
- **Inspiration**: Traditional IDS systems (Snort, Suricata, Zeek)

