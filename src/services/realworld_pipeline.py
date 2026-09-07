import pandas as pd
from src.database.models import NetworkEvent, DNSEvent
from src.database.repositories import insert_network_event, insert_dns_events_batch
from src.database.realtime_db import realtime_bus
from src.services.pipeline import run_detection_on_events
from src.utils.logging_config import logger

class RealWorldPipelineManager:
    """
    Ingests real live physical NIC traffic, stores real network events in SQLite,
    and raises real alerts when anomalous behavior occurs.
    """
    def __init__(self, buffer_size: int = 500):
        self.buffer_size = buffer_size
        self.live_net_events = []
        self.live_dns_events = []

    def handle_realworld_packet(self, event: NetworkEvent | DNSEvent, db_path: str | None = None):
        """Processes real live packet captured from physical network adapter."""
        if isinstance(event, NetworkEvent):
            self.live_net_events.append(event)
            if len(self.live_net_events) > self.buffer_size:
                self.live_net_events.pop(0)

            insert_network_event(event, db_path=db_path)
            realtime_bus.push_packet({
                "type": "network_flow",
                "timestamp": event.timestamp,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "destination_port": event.destination_port,
                "protocol": event.protocol,
                "bytes": event.bytes_sent
            })
        elif isinstance(event, DNSEvent):
            self.live_dns_events.append(event)
            if len(self.live_dns_events) > self.buffer_size:
                self.live_dns_events.pop(0)

            insert_dns_events_batch([event], db_path=db_path)
            realtime_bus.push_packet({
                "type": "dns_query",
                "timestamp": event.timestamp,
                "source_ip": event.source_ip,
                "domain": event.domain
            })

        # Evaluate real-time detection every 10 captured packets
        if len(self.live_net_events) % 10 == 0:
            self._analyze_live_stream(db_path=db_path)

    def _analyze_live_stream(self, db_path: str | None = None):
        """Evaluates detection rules against live captured NIC events."""
        if not self.live_net_events:
            return

        net_rows = [e.to_row() for e in self.live_net_events]
        cols = ["event_id", "timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "domain", "duration", "bytes_sent", "bytes_received", "connection_state", "log_source", "pcap_reference", "created_at"]
        net_df = pd.DataFrame(net_rows, columns=cols)

        dns_rows = [e.to_row() for e in self.live_dns_events]
        dns_cols = ["event_id", "timestamp", "source_ip", "domain", "query_type", "response", "ttl", "created_at"]
        dns_df = pd.DataFrame(dns_rows, columns=dns_cols) if dns_rows else pd.DataFrame(columns=dns_cols)

        alerts_count = run_detection_on_events(net_df, dns_df, db_path=db_path)
        if alerts_count > 0:
            logger.info(f"Real-world NIC pipeline generated {alerts_count} real-time alerts.")

realworld_pipeline = RealWorldPipelineManager()
