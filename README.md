# Network Intrusion Detection System (IDS)

A production-ready Python-based Network Intrusion Detection System that monitors network traffic in real-time to detect security threats using both signature-based and anomaly-based detection methods.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Detection Methods](#detection-methods)
- [Filtering](#filtering)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Authors](#authors)

## Overview

This IDS provides comprehensive network security monitoring capabilities with minimal false positives through intelligent filtering and configurable detection thresholds. The system is designed to be lightweight, extensible, and suitable for both production deployments and educational purposes.

### Key Capabilities

- Real-time TCP/IP traffic monitoring
- Dual detection methodology (signature-based and anomaly-based)
- Configurable whitelist/blacklist filtering
- Alert deduplication and rate limiting
- Flow-based traffic analysis with LRU eviction
- YAML-based configuration management
- Comprehensive logging and statistics

## Features

### Detection

- **Signature-Based Detection**
  - SYN flood attack detection
  - Port scanning detection
  - Large packet anomaly detection
  - Configurable detection thresholds

- **Anomaly-Based Detection**
  - Machine learning with Isolation Forest algorithm
  - Baseline traffic profiling
  - Statistical outlier identification
  - Adaptive threat detection

### Traffic Management

- **Flow Tracking**
  - 5-tuple flow identification (src IP, dst IP, src port, dst port, protocol)
  - LRU eviction policy for memory management
  - Automatic cleanup of inactive flows
  - Configurable flow timeout and limits

- **Packet Filtering**
  - IP address whitelisting (individual and CIDR ranges)
  - IP address blacklisting (known bad actors)
  - Port-based filtering
  - IPv4 and IPv6 support

### Alert System

- **Deduplication**
  - Configurable suppression window
  - Flow-based alert tracking
  - Ongoing attack monitoring
  - Suppression statistics

- **Rate Limiting**
  - Prevents alert storms
  - Configurable alerts per minute
  - Automatic throttling during high-threat periods

- **Logging**
  - Structured JSON format
  - Severity-based filtering
  - Alert metadata and context
  - Historical tracking

### Real-Time Statistics Display

- **Live Monitoring**
  - Updates every 10 seconds (configurable)
  - Non-blocking separate thread
  - Color-coded ANSI output

- **Metrics Displayed**
  - Packets per second (current rate)
  - Threats per second (current rate)
  - Filtered packets per second
  - Total cumulative counts
  - Active flows count

- **Top Attackers**
  - Top 5 most active sources
  - Threat count per IP
  - Time since last activity
  - Auto-filters inactive sources

- **Visual Indicators**
  - Green: Normal/low threat
  - Yellow: Moderate/warning
  - Red: High threat/critical
  - Configurable or can be disabled

## Architecture

```
┌──────────────────┐
│ Packet Capture   │ ──> Captures TCP/IP packets from network interface
│  (Scapy + Queue) │     • Threaded capture
└────────┬─────────┘     • Configurable queue size
         │
         ▼
┌──────────────────┐
│  Packet Filter   │ ──> Applies whitelist/blacklist rules
│ (Whitelist/Black)│     • IP/network filtering
└────────┬─────────┘     • Port filtering
         │
         ▼
┌──────────────────┐
│Traffic Analyzer  │ ──> Extracts features and tracks flows
│  (Flow Tracking) │     • 5-tuple flow identification
└────────┬─────────┘     • Feature extraction
         │
         ▼
┌──────────────────┐
│Detection Engine  │ ──> Applies detection rules
│ (Signatures + ML)│     • Signature matching
└────────┬─────────┘     • Anomaly detection
         │
         ▼
┌──────────────────┐
│  Alert System    │ ──> Manages and logs alerts
│  (Deduplication) │     • Deduplication
└──────────────────┘     • Rate limiting
```

## Requirements

### System Requirements

- **Operating System**: Linux, macOS, or Windows with WSL
- **Python**: 3.8 or higher
- **Permissions**: Root/sudo access (required for packet capture)
- **Memory**: 512MB minimum, 2GB recommended
- **Network**: Access to network interface for monitoring

### Python Dependencies

```
scapy>=2.5.0
scikit-learn>=1.5.0
numpy>=1.26.0
matplotlib>=3.8.0
pyyaml>=6.0
```

## Installation

### 1. Clone Repository

```bash
git clone <repository-url>
cd IDS_project
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
python -m tests.test_ids
```

Expected output: `Ran 34 tests ... OK`

## Quick Start

### Basic Usage

```bash
# Activate virtual environment
source venv/bin/activate

# Start IDS with default configuration
sudo python3 -m ids.intrusion_detection_system

# Or specify custom configuration
sudo python3 -m ids.intrusion_detection_system -c config.yaml

# Monitor specific interface
sudo python3 -m ids.intrusion_detection_system -i en0
```

### Stop the IDS

Press `Ctrl+C` for graceful shutdown. Statistics will be displayed:

```
============================================================
IDS Statistics
============================================================
Packets processed: 1523
Packets filtered (whitelisted): 487
Threats detected: 15
Threats from blacklisted sources: 3
Errors encountered: 0
============================================================
```

### Real-Time Statistics

While running, the IDS displays live statistics every 10 seconds:

```
================================================================================
IDS Real-Time Statistics - 2025-12-05 14:30:45
Uptime: 2h 15m 30s
================================================================================
RATES (per second):
  Packets processed:    45.23
  Threats detected:      2.15
  Packets filtered:     12.50

TOTALS:
  Total packets:        14852
  Total threats:          706
  Total filtered:        4123
  Unique attackers:        12
  Active flows:           234

TOP ATTACKERS:
  1. 192.168.1.100           45 threats  (5s ago)
  2. 10.0.0.15               32 threats  (12s ago)
  3. 203.0.113.42            28 threats  (18s ago)
  4. 198.51.100.7            15 threats  (45s ago)
  5. 192.168.1.200           12 threats  (1m ago)
================================================================================
```

Statistics are color-coded:
- **Green**: Normal rates, low threat levels
- **Yellow**: Moderate activity, warning levels
- **Red**: High threat activity, critical alerts

To disable statistics display:
```bash
sudo python3 -m ids.intrusion_detection_system --no-stats
```

## Configuration

### Configuration File

The IDS uses YAML configuration files for flexible customization. Default configuration file: `config.yaml`

### Key Configuration Sections

#### Network Settings

```yaml
network:
  interface: "lo0"          # Network interface to monitor
  queue_size: 1000          # Packet buffer size
  bpf_filter: ""            # Berkeley Packet Filter expression
```

#### Detection Thresholds

```yaml
detection:
  syn_flood:
    enabled: true
    rate_threshold: 1500    # Packets per second
    min_packet_count: 15
    severity: "high"
  
  port_scan:
    enabled: true
    rate_threshold: 500
    min_packet_count: 15
    severity: "medium"
```

#### Filtering Rules

```yaml
filtering:
  whitelist:
    - "127.0.0.1"           # Localhost
    - "192.168.1.0/24"      # Internal network
  
  blacklist:
    - "45.142.120.15"       # Known malicious IP
  
  whitelist_ports:
    - 443                   # HTTPS
    - 22                    # SSH
```

#### Alert Configuration

```yaml
alerting:
  log_file: "ids_alerts.log"
  min_severity: "low"
  deduplication_window: 60      # Seconds
  rate_limit_per_minute: 100    # Maximum alerts
```

#### Statistics Display Configuration

```yaml
performance:
  stats_display_enabled: true   # Enable/disable real-time display
  stats_interval: 10             # Update interval in seconds
  stats_use_colors: true         # ANSI color codes
```

### Command Line Overrides

```bash
# Override interface
sudo python3 -m ids.intrusion_detection_system -i eth0

# Override detection thresholds
sudo python3 -m ids.intrusion_detection_system --syn-flood-threshold 2000

# Disable real-time statistics display
sudo python3 -m ids.intrusion_detection_system --no-stats

# Run without config file (use defaults)
sudo python3 -m ids.intrusion_detection_system --no-config
```

## Usage

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
| `lo0` / `lo` | Loopback (local traffic) |
| `eth0` | Ethernet (Linux) |
| `en0` / `en1` | WiFi/Ethernet (macOS) |
| `wlan0` | WiFi (Linux) |

### Monitoring Alerts

**Real-time monitoring**:
```bash
tail -f ids_alerts.log
```

**Pretty-print JSON**:
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
  "timestamp": "2025-12-05T14:30:45.123456",
  "threat_type": "signature",
  "rule": "port_scan",
  "severity": "medium",
  "confidence": 1.0,
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "destination_ip": "192.168.1.2",
  "destination_port": 80,
  "status": "new",
  "alert_count": 1,
  "suppressed_count": 0,
  "description": "Potential port scanning activity detected"
}
```

## Detection Methods

### Signature-Based Detection

Detects known attack patterns using predefined rules:

#### SYN Flood Attack

**Indicators**:
- Pure SYN packets (no ACK flag)
- High packet rate (>1500 packets/second)
- Small packet sizes (<100 bytes)
- Multiple packets in flow

**Severity**: High

#### Port Scan

**Indicators**:
- SYN packets to multiple ports
- High packet rate (>500 packets/second)
- Small packet sizes (<100 bytes)
- Short flow duration (<0.5 seconds)

**Severity**: Medium

#### Large Packet

**Indicators**:
- Packet size exceeds typical MTU (>1500 bytes)

**Severity**: Low

### Anomaly-Based Detection

Uses Isolation Forest machine learning algorithm:

- **Training**: Learns baseline from normal traffic patterns
- **Detection**: Identifies statistical outliers in real-time
- **Features**: Packet size, packet rate, byte rate
- **Threshold**: Configurable (default: -0.5)

Note: Requires training on baseline traffic; disabled by default.

## Filtering

### Whitelist

**Purpose**: Completely ignore traffic from trusted sources

**Use Cases**:
- Internal corporate networks
- Trusted services (DNS, NTP)
- Monitoring infrastructure
- Development environments

**Effect**: Packets are not analyzed at all (maximum performance, zero false positives)

**Example**:
```yaml
whitelist:
  - "127.0.0.1"           # Localhost
  - "10.0.0.0/8"          # Private network
  - "192.168.1.0/24"      # Office network
```

### Blacklist

**Purpose**: Flag traffic from known bad actors with heightened sensitivity

**Use Cases**:
- Known malicious IPs
- Bot networks
- Previously detected attackers
- Threat intelligence feeds

**Effect**: Traffic is always flagged as a threat, even without matching attack patterns

**Example**:
```yaml
blacklist:
  - "45.142.120.15"       # Known attacker
  - "103.224.182.0/24"    # Bot network
```

### Port Whitelist

**Purpose**: Ignore specific ports/services

**Use Cases**:
- Trusted internal services
- High-volume legitimate traffic
- Services monitored separately

**Effect**: Any packet with whitelisted source OR destination port is ignored

**Example**:
```yaml
whitelist_ports:
  - 22    # SSH
  - 443   # HTTPS
  - 3306  # MySQL
```

### Supported Formats

- **Individual IPs**: `"192.168.1.100"`, `"::1"`
- **CIDR Networks**: `"192.168.1.0/24"`, `"10.0.0.0/8"`
- **IPv6**: `"2001:db8::/32"`, `"fe80::/10"`
- **Ports**: Integer values (1-65535)

## Testing

### Unit Tests

Run the complete test suite:

```bash
python -m tests.test_ids
```

Run statistics display tests separately:

```bash
python -m tests.test_statistics_display
```

Test coverage includes:
- Packet analysis and feature extraction
- Flow tracking and cleanup
- SYN flood detection
- Port scan detection
- Normal traffic (false positive testing)
- Anomaly detection
- Whitelist/blacklist filtering
- Alert deduplication
- Statistics tracking and rate calculation
- Real-time display formatting
- Configuration integration

### PCAP File Testing

Test with synthetic attack traffic:

```bash
python -m tests.test_ids --pcap
```

Generates a PCAP file containing:
- 20 normal packets (ACK flags)
- 50 SYN flood packets (from different sources)
- 80 port scan packets (to sequential ports)

### Live Network Testing

Test on real network traffic:

```bash
sudo python3 -m tests.test_ids --live en0
```

**Note**: Anomaly detection is disabled for live tests to prevent false positives.

### Test with Custom PCAP

```bash
python -m tests.test_ids --pcap /path/to/capture.pcap
```

## Project Structure

```
IDS_project/
├── ids/                              # Main IDS package
│   ├── __init__.py
│   ├── intrusion_detection_system.py  # Main orchestration & CLI
│   ├── packet_capture.py              # Network packet capture
│   ├── traffic_analyzer.py            # Flow tracking & features
│   ├── detection_engine.py            # Threat detection logic
│   ├── alert_system.py                # Alert management
│   ├── packet_filter.py               # Whitelist/blacklist filtering
│   ├── statistics_display.py          # Real-time stats display
│   └── config_loader.py               # Configuration management
│
├── tests/                            # Test suite
│   ├── __init__.py
│   ├── test_ids.py                   # Unit & integration tests
│   └── test_statistics_display.py    # Statistics display tests
│
├── config.yaml                       # Configuration file
├── requirements.txt                  # Python dependencies
├── pyproject.toml                    # Project metadata
├── README.md                         # This file
├── ids_alerts.log                    # Generated alert log (JSON)
└── ids.log                           # System log
```

## Documentation

### User Guides

- **Configuration Guide**: `config.yaml` with inline comments
- **Whitelist/Blacklist Guide**: `WHITELIST_BLACKLIST_GUIDE.md`
- **Integration Guide**: `README_INTEGRATION.md`

### Technical Documentation

- **Implementation Summary**: `IMPLEMENTATION_SUMMARY.md`
- **Bug Fix Summary**: `BUGFIX_SUMMARY.md`
- **API Documentation**: Inline docstrings in all modules

### Getting Help

1. Check the configuration file: `config.yaml`
2. Review logs: `ids.log` and `ids_alerts.log`
3. Run tests: `python -m tests.test_ids`
4. Enable debug logging: Set `logging.level: "DEBUG"` in config

## Performance

### Typical Resource Usage

- **CPU**: 5-15% on moderate traffic (1000 packets/sec)
- **Memory**: ~100MB baseline + ~1KB per tracked flow
- **Disk I/O**: Minimal (alert logging only)
- **Statistics Display**: <0.1% CPU, ~1MB memory (for 60s window)

### Performance Tuning

#### High-Traffic Networks

```yaml
network:
  queue_size: 5000

flow_tracking:
  max_flows: 50000
  flow_timeout: 60
```

#### Low-Resource Systems

```yaml
network:
  queue_size: 500

flow_tracking:
  max_flows: 1000
  flow_timeout: 120
```

#### Reduce False Positives

```yaml
detection:
  syn_flood:
    rate_threshold: 2000    # Less sensitive
    min_packet_count: 20
  
  port_scan:
    rate_threshold: 800
    min_packet_count: 20
```

## Troubleshooting

### Permission Denied

**Problem**: `PermissionError` when starting IDS

**Solution**:
```bash
sudo python3 -m ids.intrusion_detection_system -i en0
```

Packet capture requires root privileges to access raw sockets.

### No Packets Captured

**Symptoms**: IDS starts but shows 0 threats and 0 packets processed

**Solutions**:

1. Verify interface exists and is up:
   ```bash
   ifconfig
   ```

2. Check for traffic on interface:
   ```bash
   sudo tcpdump -i en0 -c 10
   ```

3. Try loopback interface:
   ```bash
   sudo python3 -m ids.intrusion_detection_system -i lo0
   # Generate traffic: curl http://localhost:8000
   ```

### Statistics Not Updating

**Symptoms**: Statistics display shows zeros or doesn't update

**Solutions**:

1. Check you're monitoring the correct interface:
   ```bash
   # Find active network interface
   ifconfig | grep -B 2 "status: active"
   
   # Restart with correct interface
   sudo python3 -m ids.intrusion_detection_system -i en0
   ```

2. Verify traffic is flowing:
   ```bash
   # Generate test traffic on loopback
   ping 127.0.0.1
   
   # Or curl to local service
   curl http://localhost:8000
   ```

3. Check statistics are enabled in config:
   ```yaml
   performance:
     stats_display_enabled: true
   ```

4. Ensure you haven't used `--no-stats` flag

### Colors Not Displaying

**Symptoms**: Statistics show with `^[[92m` type codes instead of colors

**Solutions**:

1. Your terminal may not support ANSI colors. Disable them:
   ```yaml
   performance:
     stats_use_colors: false
   ```

2. Or use a modern terminal emulator (iTerm2, GNOME Terminal, Windows Terminal)

### High False Positive Rate

**Symptoms**: Normal HTTPS traffic triggering alerts

**Solutions**:

1. Increase detection thresholds in `config.yaml`:
   ```yaml
   detection:
     syn_flood:
       rate_threshold: 2000    # Increase from 1500
     port_scan:
       rate_threshold: 800     # Increase from 500
   ```

2. Add trusted networks to whitelist:
   ```yaml
   filtering:
     whitelist:
       - "192.168.1.0/24"
   ```

3. Disable anomaly detection for production:
   ```yaml
   detection:
     anomaly:
       enabled: false
   ```

### Configuration Errors

**Problem**: Invalid YAML syntax

**Check syntax**:
```bash
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

**Common issues**:
- Incorrect indentation (YAML is whitespace-sensitive)
- Missing quotes around IP addresses with special characters
- Invalid CIDR notation

## Contributing

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd IDS_project

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development tools
pip install pytest black flake8

# Run tests
python -m tests.test_ids

# Run linter
flake8 ids/ tests/
```

### Contribution Guidelines

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Add tests for new features
4. Ensure all tests pass: `python -m tests.test_ids`
5. Follow PEP 8 code style
6. Update documentation (README and docstrings)
7. Submit pull request with detailed description

### Code Style

- Follow PEP 8 conventions
- Maximum line length: 100 characters
- Use type hints where applicable
- Document all public methods and classes
- Write descriptive commit messages

## Authors

**Ryan Winn**

## Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **scikit-learn**: Machine learning framework for anomaly detection
- **Inspiration**: Traditional IDS systems (Snort, Suricata, Zeek)

## Version History

### Version 0.1.0 (Current)

**Features**:
- Real-time TCP/IP traffic monitoring
- Signature-based detection (SYN flood, port scan, large packets)
- Anomaly-based detection with machine learning
- Whitelist/blacklist filtering (IP, network, port)
- Alert deduplication and rate limiting
- Real-time statistics display with color-coded output
- YAML configuration management
- Comprehensive test suite (55 unit tests)
- IPv4 and IPv6 support

**Known Limitations**:
- TCP only (UDP/ICMP not supported)
- Single interface monitoring
- No payload inspection
- No distributed deployment
- Real-time only (no offline PCAP analysis in production mode)

**Planned Features (Phase 3)**:
- SQLite database logging
- Email notifications
- UDP protocol support
- Web-based dashboard
- PCAP export for suspicious flows

---

**Status**: Production-ready for TCP traffic monitoring

**Last Updated**: December 5, 2025