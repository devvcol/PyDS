import datetime
import logging
import threading
from queue import Queue

from scapy.all import *


class PacketCapture:
    def __init__(self, config):
        self.config = config
        self.pqueue = Queue(maxsize=1000)
        self.running = False
        self.sniffer = None
        self.stats = {
            "packets": 0,
            "bytes": 0,
            "start_time": None,
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
        }

        # logger setup copied lol
        logging.basicConfig(
            filename=config.get("log_file", "ids_capture.log"),
            level=config.get("log_level", logging.INFO),
            format="%(asctime)s - %(levelname)s - %(message)s",
        )
        self.logger = logging.getLogger("PacketCapture")

    def packet_capture(self):
        self.running = True
        self.stats["start_time"] = datetime.now()

        interface = self.config.get("interface", None)
        pfilter = self.config.get("filter", None)

        try:
            self.sniffer = AsyncSniffer(
                iface=interface, filter=pfilter, prn=self.process_packet, store=False
            )

            self.sniffer.start()
            self.logger.info(f"Capture started on {interface}")

            self.processing_thread = threading.Thread(
                target=self.packet_worker, daemon=True
            )

            self.processing_thread.start()

            return True

        except Exception as e:
            self.running = False
            self.logger.error(f"Error capturing packets: {e}")
            return False

    def stop_capture(self):
        if not self.running:
            return

        self.running = False

        if self.sniffer:
            self.sniffer.stop()

        self.logger.info(
            f"Packet capture stopped. {self.stats['packets']} packets captured"
            f"({self.stats['bytes'] / 1024:.2f} KB)"
        )
        return self.stats

    def process_packet(self, packet):
        self.stats["packets"] += 1

        if hasattr(packet, "len"):
            self.stats["bytes"] += packet.len

        if TCP in packet:
            self.stats["protocols"]["TCP"] += 1
        elif UDP in packet:
            self.stats["protocols"]["UDP"] += 1
        elif ICMP in packet:
            self.stats["protocols"]["ICMP"] += 1
        else:
            self.stats["protocols"]["Other"] += 1

        self.pqueue.put(packet, block=True, timeout=0.1)

    # PACKETS KEPT DROPPING. NEEDED PACKET WORKER FOR PROCESSING FLOW>>>>
    def packet_worker(self):
        while (
            self.running or not self.pqueue.empty()
        ):  # is capture running or is there packets in queue
            try:
                packet = self.pqueue.get(block=True, timeout=0.5)
                if self.config.get("callback"):
                    self.config["callback"](packet)
                self.pqueue.task_done()
            except Exception as e:
                if isinstance(e, TimeoutError) or isinstance(e, queue.Empty):
                    continue
            
                import traceback
                error_msg = traceback.format_exc()
            
                self.logger.error(f"Error processing packet: {str(e)}\n{error_msg}")

    def get_stats(self):
        return self.stats.copy()
