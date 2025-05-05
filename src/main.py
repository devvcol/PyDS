# main.py
import yaml
import time
import os
import signal
import sys
from datetime import datetime

from packet_capture import PacketCapture
from rules_engine import RuleEngine
from detector import Detector

def create_log_directories():
    os.makedirs("logs", exist_ok=True)

def load_config():
    with open("config/settings.yaml", "r") as f:
        return yaml.safe_load(f)

def print_banner():
    banner = """
    +-----------------------------------+
    |           PyDS - v0.1.0           |
    |     Simple Intrusion Detection    |
    +-----------------------------------+
    """
    print(banner)

def signal_handler(sig, frame): # stack overflow
    print("\nShutting down IDS...")
    global running
    running = False

def display_status(capture, detector, start_time):
    stats = capture.get_stats()
    runtime = time.time() - start_time
    
    os.system('cls' if os.name == 'nt' else 'clear')

    print("\n--- IDS Status ---")
    print(f"Runtime: {int(runtime // 3600)}h {int((runtime % 3600) // 60)}m {int(runtime % 60)}s")
    print(f"Packets captured: {stats.get('packets', 0)}")
    print(f"Alerts generated: {detector.gen_alert_cnt()}")
    
    protocols = stats.get('protocols', {})
    print("\nProtocol Distribution:")
    for proto, count in protocols.items():
        print(f"- {proto}: {count}")
    
    alerts = detector.gen_alerts(5)
    if alerts:
        print("\nRecent Alerts:")
        for alert in reversed(alerts):
            ts = alert.get('timestamp').strftime("%H:%M:%S") 
            name = alert.get('rule_name', '')
            severity = alert.get('severity', '').upper()
            src = alert.get('src_ip', 'unknown')
            print(f"[{severity}] {ts} - {name} - {src}")

def main():
    global running
    running = True
    
    signal.signal(signal.SIGINT, signal_handler)
    
    create_log_directories()
    
    config = load_config()
    
    print_banner()
    
    rules_file = "config/rules.yaml"
    rule_engine = RuleEngine(rules_file)
    detector = Detector(config, rule_engine)
    
    capture_config = config.get("capture", {})
    capture_config["callback"] = detector.packet_analyzer
    
    capture = PacketCapture(capture_config)
    if not capture.packet_capture():
        print("Failed to start packet capture. Exiting.")
        return
    
    print(f"IDS started. Monitoring network traffic... (Press Ctrl+C to stop)")
    start_time = time.time()
    
    status_interval = 5  # seconds
    last_status = time.time()
    
    try:
        while running:
            time.sleep(0.1)  # apparently good for CPU usage?
            
            if time.time() - last_status >= status_interval:
                display_status(capture, detector, start_time)
                last_status = time.time()
    finally:
        capture.stop_capture()
        print("\nIDS stopped.")

if __name__ == "__main__":
    main()