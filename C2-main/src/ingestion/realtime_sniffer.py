import threading
import time
import uuid
from typing import Callable, Any
from src.database.models import NetworkEvent, DNSEvent
from src.services.admin_permission_service import get_admin_permission_status
from src.utils.logging_config import logger
from src.utils.time_utils import current_iso8601

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, sniff
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

class RealTimeSnifferEngine:
    """
    Real-time packet sniffer worker. Operates strictly when Admin Permission is GRANTED.
    Runs in a dedicated background thread and forwards live packets to callback.
    """
    def __init__(self, callback_fn: Callable[[NetworkEvent | DNSEvent], None] | None = None):
        self.callback_fn = callback_fn
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._is_active = False
        self.interface = "eth0"
        self.db_path = None
        self.packets_captured_count = 0

    def is_running(self) -> bool:
        return self._is_active and self._thread is not None and self._thread.is_alive()

    def start_sniffing(self, interface: str = "eth0", db_path: str | None = None) -> bool:
        """Starts real-time background packet sniffer after checking Admin Permission."""
        perm = get_admin_permission_status(db_path=db_path)
        if not perm.get("is_granted"):
            logger.warning("Cannot start live sniffing: Admin permission is NOT GRANTED.")
            raise PermissionError("Admin permission required to scan live network packets.")

        if self.is_running():
            logger.info("Sniffer engine is already running.")
            return True

        self.interface = interface
        self.db_path = db_path
        self._stop_event.clear()
        self.packets_captured_count = 0

        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        self._is_active = True
        logger.info(f"Real-time packet sniffer started on interface '{interface}'")
        return True

    def stop_sniffing(self) -> None:
        """Stops the real-time packet sniffer thread."""
        self._stop_event.set()
        self._is_active = False
        logger.info("Real-time packet sniffer stop requested.")

    def _sniff_loop(self):
        """Worker loop for capturing live packets."""
        if HAS_SCAPY:
            try:
                def process_packet(pkt):
                    if self._stop_event.is_set():
                        return True
                    
                    if IP in pkt:
                        ip_layer = pkt[IP]
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else "ip"
                        src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else None
                        dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else None
                        now = current_iso8601()
                        
                        net_evt = NetworkEvent(
                            event_id=str(uuid.uuid4()),
                            timestamp=now,
                            source_ip=src_ip,
                            source_port=src_port,
                            destination_ip=dst_ip,
                            destination_port=dst_port,
                            protocol=proto,
                            log_source="realtime_sniffer"
                        )
                        self.packets_captured_count += 1
                        
                        if self.callback_fn:
                            self.callback_fn(net_evt)

                        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                            qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                            dns_evt = DNSEvent(
                                event_id=str(uuid.uuid4()),
                                timestamp=now,
                                source_ip=src_ip,
                                domain=qname,
                                query_type="A"
                            )
                            if self.callback_fn:
                                self.callback_fn(dns_evt)

                sniff(
                    iface=self.interface if self.interface != "all" else None,
                    prn=process_packet,
                    stop_filter=lambda p: self._stop_event.is_set(),
                    store=False,
                    timeout=1.0
                )
            except Exception as e:
                logger.error(f"Scapy sniffing error: {e}")
        else:
            logger.warning("Scapy not available. Sniffer running in simulated loop mode.")
            while not self._stop_event.is_set():
                time.sleep(1.0)

_global_sniffer = RealTimeSnifferEngine()
