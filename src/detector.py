import logging
from datetime import *


class Detector:
    def __init__(self, config, rule_engine):
        self.config = config
        self.rule_engine = rule_engine
        self.alerts = []
        self.alert_cnt = 0

        # logger again
        logging.basicConfig(
            filename=config.get("detection", {}).get("log_file", "logs/detection.log"),
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )
        self.logger = logging.getLogger("Detector")

        self.logger.info("Detector initialized")

    def packet_analyzer(self, packet):
        triggered_rules = self.rule_engine.check_packet(packet)

        for rule in triggered_rules:
            self.gen_alert(rule, packet)

        if self.alert_cnt % 100 == 0:
            self.rule_engine.cleanup()

        return len(triggered_rules) > 0

    def gen_alert(self, rule, packet):
        from scapy.all import IP, TCP, UDP

        alert_inf = {
            "timestamp": datetime.now(),
            "rule_id": rule.id,
            "rule_name": rule.name,
            "severity": rule.severity,
            "protocol": rule.protocol,
        }

        if IP in packet:
            alert_inf["src_ip"] = packet[IP].src
            alert_inf["dst_ip"] = packet[IP].dst

            if TCP in packet:
                alert_inf["src_port"] = packet[TCP].sport
                alert_inf["dst_port"] = packet[TCP].dport
            elif UDP in packet:
                alert_inf["src_port"] = packet[UDP].sport
                alert_inf["dst_port"] = packet[UDP].dport

        self.logger.warning(f"ALERT: {rule.name} - {alert_inf}")
        self.alerts.append(alert_inf)
        self.alert_cnt += 1

        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]

    def gen_alerts(self, cnt=10):
        return self.alerts[-cnt:]

    def gen_alert_cnt(self):
        return self.alert_cnt
