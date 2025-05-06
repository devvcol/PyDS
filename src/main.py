import rich
import yaml
import time
import os
import signal
import sys
from datetime import datetime

#rich cli imports
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.align import Align

from packet_capture import PacketCapture
from rules_engine import RuleEngine
from detector import Detector

console = Console()

def create_log_directories():
    os.makedirs("logs", exist_ok=True)

def load_config():
    with open("config/settings.yaml", "r") as f:
        return yaml.safe_load(f)

def signal_handler(sig, frame): # stack overflow
    console.print("\nShutting down IDS...", style="yellow")
    global running
    running = False

def display_status(capture, detector, start_time, live, layout):
    stats = capture.get_stats()
    runtime = time.time() - start_time
    runtime_str = f"{int(runtime // 3600)}h {int((runtime % 3600) // 60)}m {int(runtime % 60)}s" # for Rich CLI
    
    # CLI header
    header_content = Text("PyDS - Python Intrusion Detection System", style="bold white")
    centered_header = Align.center(header_content)
    layout["header"].update(Panel(centered_header, border_style="blue"))

    # left table for the stats
    stats_table = Table()
    stats_table.add_column("Statistic", style="cyan")
    stats_table.add_column("Value", style="green")
    
    stats_table.add_row("Runtime", runtime_str)
    stats_table.add_row("Packets captured", str(stats.get('packets', 0)))
    stats_table.add_row("Alerts generated", str(detector.gen_alert_cnt()))

    # adds our protocols dynamically
    protocols = stats.get('protocols', {})
    for proto, count in protocols.items():
        stats_table.add_row(f"Protocol: {proto}", str(count))

    layout["stats"].update(Panel(stats_table, title="Packet Statistics", border_style="green"))

    # right table for the alerts 
    alerts = detector.gen_alerts(5)
    alerts_table = Table()
    alerts_table.add_column("Time", style="cyan")
    alerts_table.add_column("Severity", style="white")
    alerts_table.add_column("Rule", style="yellow")
    alerts_table.add_column("Source", style="magenta")

    if alerts:
        for alert in reversed(alerts):
            ts = alert.get('timestamp').strftime("%H:%M:%S")
            name = alert.get('rule_name', '')
            severity = alert.get('severity', '').upper()
            src = alert.get('src_ip', 'unknown')
            
            severity_style = "green"
            if severity == "HIGH":
                severity_style = "bold red"
            elif severity == "MEDIUM":
                severity_style = "bold yellow"
            
            alerts_table.add_row(ts, Text(severity, style=severity_style), name, src)
    
    layout["alerts"].update(Panel(alerts_table, title="Alerts", border_style="red"))
    
    live.update(layout)

def main():
    global running
    running = True
    
    signal.signal(signal.SIGINT, signal_handler)
    
    create_log_directories()
    
    config = load_config()
    
    rules_file = "config/rules.yaml"
    rule_engine = RuleEngine(rules_file)
    detector = Detector(config, rule_engine)
    
    capture_config = config.get("capture", {})
    capture_config["callback"] = detector.packet_analyzer
    
    capture = PacketCapture(capture_config)
    if not capture.packet_capture():
        console.print("Failed to start packet capture. Exiting.", style="bold red")
        return
    
    start_time = time.time()
    
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body")
    )
    layout["body"].split_row(
        Layout(name="stats"),
        Layout(name="alerts")
    )
    
    # live display so tables can update 
    with Live(layout, refresh_per_second=4, screen=True) as live:
        try:
            while running:
                display_status(capture, detector, start_time, live, layout)
                time.sleep(0.25)
        except KeyboardInterrupt:
            running = False
        finally:
            capture.stop_capture()
            console.print("\nIDS stopped.", style="bold red")

if __name__ == "__main__":
    main()