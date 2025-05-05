import re
from collections import defaultdict
from datetime import *

import yaml


class Rule:
    def __init__(self, rule):
        self.id = rule.get("id")
        self.name = rule.get("name")
        self.enabled = rule.get("enabled", True)
        self.type = rule.get("type")
        self.protocol = rule.get("protocol", "").lower()
        self.severity = rule.get("severity", "medium")

        if self.type == "threshold":
            self.threshold = rule.get("threshold", 10)
            self.timeframe = rule.get("timeframe", 60)
            self.match_field = rule.get("match_field", "src_ip")
        elif self.type == "pattern":
            self.pattern = rule.get("pattern")
            self.regex = re.compile(self.pattern)

    def __str__(self):
        return f"Rule: {self.id}: {self.name} ({self.severity})"


class RuleEngine:
    def __init__(self, rules_file):
        self.rules = []
        self.traffic_log = defaultdict(list)  # no KeyErrors

        with open(rules_file, "r") as f:
            rules_data = yaml.safe_load(f)

        for rule_data in rules_data:
            rule = Rule(rule_data)
            if rule.enabled == True:
                self.rules.append(rule)  # add our enables yaml rules
        print(f"Loaded: {len(self.rules)} rules")

    def check_packet(self, packet):
        packet_info = self.get_packet_info(packet)
        if not packet_info:
            return []
        #print(f"DEBUG - Packet: {packet_info.get('protocol')} from {packet_info.get('src_ip')}:{packet_info.get('src_port')} to {packet_info.get('dst_ip')}:{packet_info.get('dst_port')}")
        triggered_rules = []
        
        for rule in self.rules:  # each yaml rule
            if rule.protocol and packet_info["protocol"] != rule.protocol:
                continue
            if rule.type == "pattern" and self.check_pattern(rule, packet):
                #print(f"DEBUG - Rule {rule.id} pattern matched!")
                triggered_rules.append(rule)
            elif rule.type == "threshold" and self.check_threshold(rule, packet_info):
                #print(f"DEBUG - Rule {rule.id} threshold exceeded!")
                triggered_rules.append(rule)

        return triggered_rules

    def get_packet_info(self, packet):
        from scapy.all import ICMP, IP, TCP, UDP

        info = {
            "timestamp": datetime.now(),
            "size": len(packet) if hasattr(packet, "__len__") else 0,
        }

        if IP in packet:
            info["src_ip"] = packet[IP].src
            info["dst_ip"] = packet[IP].dst

            if TCP in packet:
                info["protocol"] = "tcp"
                info["src_port"] = packet[TCP].sport
                info["dst_port"] = packet[TCP].dport
                info["flags"] = packet[TCP].flags

            elif UDP in packet:
                info["protocol"] = "udp"
                info["src_port"] = packet[UDP].sport
                info["dst_port"] = packet[UDP].dport

            elif ICMP in packet:
                info["protocol"] = "icmp"
                info["icmp_type"] = packet[ICMP].type

            else:
                info["protocol"] = "other"

            return info

        return None

    def check_pattern(self, rule, packet):
        if not rule.pattern:
            return False

        packet_bytes = bytes(packet)

        if rule.regex and rule.regex.search(str(packet_bytes)):
            return True

        if rule.pattern.encode() in packet_bytes:
            return True

        return False

    def check_threshold(self, rule, packet_info):
        time = datetime.now()

        if rule.match_field in packet_info:
            key = packet_info[rule.match_field]
            rule_key = f"{rule.id}:{key}"
            
            # for SSH Brute Force detection (Rule ID 1003)
            if rule.id == "1003":
                if packet_info.get("dst_port") != 22 and packet_info.get("src_port") != 22:
                    return False
                    
            # for TCP Port Scan detection (Rule ID 1001)
            if rule.id == "1001":
                dst_ip = packet_info.get("dst_ip")
                dst_port = packet_info.get("dst_port")
                
                if dst_ip and dst_port:
                    scan_key = f"{rule_key}:{dst_ip}:{dst_port}"
                    
                    if scan_key in self.traffic_log:
                        self.traffic_log[scan_key].append(time)
                        return False
                    else:
                        self.traffic_log[scan_key] = [time]
                        
                    unique_ports = set()
                    scan_prefix = f"{rule.id}:{key}:{dst_ip}:"
                    
                    for k in self.traffic_log.keys():
                        if k.startswith(scan_prefix):
                            port = k.split(":")[-1]
                            if self.traffic_log[k] and (time - max(self.traffic_log[k])).total_seconds() <= rule.timeframe:
                                unique_ports.add(port)
                    
                    if len(unique_ports) >= rule.threshold:
                        return True
                    return False
                    
            self.traffic_log[rule_key].append(time)
            
            cutoff = time - timedelta(seconds=rule.timeframe)
            self.traffic_log[rule_key] = [t for t in self.traffic_log[rule_key] if t > cutoff]
            
            if len(self.traffic_log[rule_key]) >= rule.threshold:
                return True

        return False

    def cleanup(self):  # mem bloat
        cutoff = datetime.now() - timedelta(minutes=10)
        key_remove = []

        for k, t in self.traffic_log.items():
            if not t or max(t) < cutoff:
                key_remove.append(k)
        for k in key_remove:
            del self.traffic_log[k]
