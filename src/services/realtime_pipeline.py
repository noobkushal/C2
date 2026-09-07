import pandas as pd
from src.database.models import NetworkEvent, DNSEvent
from src.database.repositories import insert_network_event, insert_network_events_batch
from src.database.realtime_db import realtime_bus
from src.services.pipeline import run_detection_on_events
from src.services.admin_permission_service import get_admin_permission_status
from src.utils.logging_config import logger

class RealTimePipelineManager:
    """
    Processes real-time streaming events from live sniffer,
    maintains a rolling buffer, runs live detection checks, and raises real-time issues/alerts.
    """
    def __init__(self, window_capacity: int = 500):
        self.window_capacity = window_capacity
        self.live_net_events = []
        self.live_dns_events = []

    def handle_live_event(self, event: NetworkEvent | DNSEvent, db_path: str | None = None):
        """Callback handler invoked by real-time sniffer for each live packet."""
        # 1. Enforce Admin Permission check
        perm = get_admin_permission_status(db_path=db_path)
        if not perm.get("is_granted"):
            return

        if isinstance(event, NetworkEvent):
            self.live_net_events.append(event)
            if len(self.live_net_events) > self.window_capacity:
                self.live_net_events.pop(0)

            insert_network_event(event, db_path=db_path)
            realtime_bus.push_packet({
                "type": "network",
                "timestamp": event.timestamp,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "destination_port": event.destination_port,
                "protocol": event.protocol
            })
        elif isinstance(event, DNSEvent):
            self.live_dns_events.append(event)
            if len(self.live_dns_events) > self.window_capacity:
                self.live_dns_events.pop(0)

            realtime_bus.push_packet({
                "type": "dns",
                "timestamp": event.timestamp,
                "source_ip": event.source_ip,
                "domain": event.domain
            })

        # Periodically run live detection checks on streaming window
        if len(self.live_net_events) % 10 == 0:
            self._evaluate_live_window(db_path=db_path)

    def _evaluate_live_window(self, db_path: str | None = None):
        """Runs detection rules against the current rolling streaming window."""
        if not self.live_net_events:
            return

        net_rows = [e.to_row() for e in self.live_net_events]
        cols = ["event_id", "timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "domain", "duration", "bytes_sent", "bytes_received", "connection_state", "log_source", "pcap_reference", "created_at"]
        net_df = pd.DataFrame(net_rows, columns=cols)

        dns_rows = [e.to_row() for e in self.live_dns_events]
        dns_cols = ["event_id", "timestamp", "source_ip", "domain", "query_type", "response", "ttl", "created_at"]
        dns_df = pd.DataFrame(dns_rows, columns=dns_cols) if dns_rows else pd.DataFrame(columns=dns_cols)

        alerts_raised = run_detection_on_events(net_df, dns_df, db_path=db_path)
        if alerts_raised > 0:
            logger.info(f"Real-time pipeline raised {alerts_raised} live security alerts.")

realtime_pipeline_manager = RealTimePipelineManager()
