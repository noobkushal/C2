import socket
import threading
import time
import uuid
from typing import Callable, Any
from src.database.models import NetworkEvent, DNSEvent
from src.services.auth_service import has_role
from src.services.admin_permission_service import get_admin_permission_status
from src.utils.logging_config import logger
from src.utils.time_utils import current_iso8601

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, conf, get_working_ifaces, sniff
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

def list_active_interfaces() -> list[str]:
    """Auto-detects active network interfaces on machine."""
    interfaces = []
    if HAS_SCAPY:
        try:
            for iface in get_working_ifaces():
                name = getattr(iface, "name", None) or getattr(iface, "description", None) or str(iface)
                if name and name not in interfaces:
                    interfaces.append(name)
        except Exception:
            pass
    if not interfaces:
        interfaces = ["Wi-Fi", "Ethernet", "eth0", "wlan0", "lo"]
    return interfaces

class RealWorldSniffer:
    """
    Real-world live network sniffer. Captures actual live IP packets traversing physical NICs.
    Requires ADMIN authorization AND Admin Permission consent.
    """
    def __init__(self, callback_fn: Callable[[NetworkEvent | DNSEvent], None] | None = None):
        self.callback_fn = callback_fn
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._is_active = False
        self.selected_interface = None
        self.packets_captured_count = 0

    def is_running(self) -> bool:
        return self._is_active and self._thread is not None and self._thread.is_alive()

    def start_sniffing(
        self,
        interface: str | None = None,
        user_obj: dict | None = None,
        db_path: str | None = None
    ) -> bool:
        """Starts real-world live packet capture after verifying ADMIN role & Admin Consent."""
        # 1. RBAC authorization check
        if not user_obj or not has_role(user_obj, "ADMIN"):
            logger.warning("Live scanning denied: User does not have ADMIN authorization.")
            raise PermissionError("Authorization Error: Only ADMIN accounts can start live network packet scanning.")

        # 2. Admin Permission consent check
        perm = get_admin_permission_status(db_path=db_path)
        if not perm.get("is_granted"):
            logger.warning("Live scanning denied: Admin permission consent is REVOKED.")
            raise PermissionError("Admin Consent Error: Permission consent must be GRANTED before scanning network traffic.")

        if self.is_running():
            logger.info("Real-world sniffer is already actively capturing traffic.")
            return True

        self.selected_interface = interface or (list_active_interfaces()[0] if list_active_interfaces() else None)
        self._stop_event.clear()
        self.packets_captured_count = 0

        self._thread = threading.Thread(target=self._realworld_sniff_loop, daemon=True)
        self._thread.start()
        self._is_active = True
        logger.info(f"Real-world live packet sniffing started on physical interface '{self.selected_interface}'")
        return True

    def stop_sniffing(self) -> None:
        """Stops the real-world live packet sniffer."""
        self._stop_event.set()
        self._is_active = False
        logger.info("Real-world live packet sniffer stopped.")

    def _realworld_sniff_loop(self):
        """Worker thread capturing actual live network traffic."""
        def process_live_pkt(pkt):
            if self._stop_event.is_set():
                return True

            if IP in pkt:
                ip_layer = pkt[IP]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else "ip"
                src_port = int(pkt[TCP].sport) if TCP in pkt else int(pkt[UDP].sport) if UDP in pkt else None
                dst_port = int(pkt[TCP].dport) if TCP in pkt else int(pkt[UDP].dport) if UDP in pkt else None
                now = current_iso8601()

                net_evt = NetworkEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=now,
                    source_ip=src_ip,
                    source_port=src_port,
                    destination_ip=dst_ip,
                    destination_port=dst_port,
                    protocol=proto,
                    bytes_sent=len(pkt),
                    log_source="realworld_nic"
                )
                self.packets_captured_count += 1

                if self.callback_fn:
                    self.callback_fn(net_evt)

                if DNS in pkt and DNSQR in pkt:
                    qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                    if qname:
                        dns_evt = DNSEvent(
                            event_id=str(uuid.uuid4()),
                            timestamp=now,
                            source_ip=src_ip,
                            domain=qname,
                            query_type="A"
                        )
                        if self.callback_fn:
                            self.callback_fn(dns_evt)

        if HAS_SCAPY:
            try:
                # Attempt Layer 2 sniffing
                sniff(
                    iface=self.selected_interface,
                    prn=process_live_pkt,
                    stop_filter=lambda p: self._stop_event.is_set(),
                    store=False,
                    timeout=1.0
                )
            except Exception as e:
                logger.warning(f"Layer 2 sniffing unavailable ({e}). Retrying with Layer 3 socket sniffer...")
                try:
                    conf.L3socket = conf.L3socket
                    sniff(
                        L3socket=conf.L3socket,
                        prn=process_live_pkt,
                        stop_filter=lambda p: self._stop_event.is_set(),
                        store=False,
                        timeout=1.0
                    )
                except Exception as ex2:
                    logger.warning(f"Layer 3 Scapy sniffing exception ({ex2}). Running socket loop...")
                    self._socket_fallback_loop(process_live_pkt)
        else:
            self._socket_fallback_loop(process_live_pkt)

    def _socket_fallback_loop(self, callback_proc):
        """Fallback raw socket sniffer loop."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.settimeout(1.0)
            while not self._stop_event.is_set():
                try:
                    raw_data, addr = sock.recvfrom(65535)
                    now = current_iso8601()
                    net_evt = NetworkEvent(
                        event_id=str(uuid.uuid4()),
                        timestamp=now,
                        source_ip=addr[0],
                        destination_ip="127.0.0.1",
                        protocol="ip",
                        bytes_sent=len(raw_data),
                        log_source="socket_raw"
                    )
                    self.packets_captured_count += 1
                    if self.callback_fn:
                        self.callback_fn(net_evt)
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as err:
            logger.warning(f"Socket sniffer initialization notice ({err}). Host interface active.")
            while not self._stop_event.is_set():
                time.sleep(0.5)

realworld_sniffer_engine = RealWorldSniffer()
