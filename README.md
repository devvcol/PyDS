# PYDS (Python Intrusion Detection System)

Lightweight, YAML rule-based IDS written in Python using Scapy. Monitors and detects malicious network activity via pattern matching and behavioral analysis.

Made purely for educational purposes.

### Includes:
- **Realtime Network Monitoring**: Capture and analyze packets from any chosen network iface
- **Extensible Rule System**: YAML-based rule configuration for easy customization
- **Live Status Updates**: Real-time console reporting of system activity

### Installation:
```git clone https://github.com/devvcol/PyDS.git```

```cd pyds```

```pip install requirements.txt``` contains the scapy and pyyaml pips

The two config files (settings.yaml & rules.yaml) should be modified to match your specific environment, such as the network interface (most likely eth0).

### Running the IDS:
```sudo python main.py```
**Needs sudo to run for optimal packet capture**

### Detections:
- TCP Port Scans
- ICMP Floods
- SSH Brute Force Attempts
- Suspicious User-Agent Strings
- Executable File Downloads

### Future additions

- [ ] Web Dashboard
- [ ] PCAP import/export
