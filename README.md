# Python Intrusion Detection System (IDS)

A real-time **Intrusion Detection System** (IDS) implemented in Python.  
This IDS uses **signature-based** and **anomaly-based** detection to monitor network traffic and identify potential threats like SYN floods, port scans, and abnormal behavior.

---

## Features

- **Packet Capture**: Real-time sniffing of TCP/IP packets using [Scapy](https://scapy.net/).  
- **Traffic Analysis**: Extracts flow statistics and packet-level features such as packet size, rate, byte rate, TCP flags, and window size.  
- **Signature-Based Detection**: Detects known attacks (SYN flood, port scans) based on predefined rules.  
- **Anomaly Detection**: Uses [IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html) to detect unusual traffic patterns.  
- **Alert System**: Logs alerts to file and console; can be extended for Slack, email, or SIEM notifications.  
- **Test Mode**: Simulate network attacks with mock packets for testing without live traffic.

---

## Requirements

- Python 3.10+  
- [Scapy](https://scapy.net/)  
- [NumPy](https://numpy.org/)  
- [scikit-learn](https://scikit-learn.org/stable/)  

Install dependencies:

```bash
pip install scapy numpy scikit-learn
