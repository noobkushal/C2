from collections import deque
import threading
from typing import Any

class RealTimeEventBus:
    """
    In-memory ring buffer and real-time event dispatcher for live network packet feeds and alerts.
    """
    def __init__(self, max_buffer_size: int = 500):
        self.max_buffer_size = max_buffer_size
        self.live_packets = deque(maxlen=max_buffer_size)
        self.live_alerts = deque(maxlen=max_buffer_size)
        self._lock = threading.Lock()
        self._listeners = []

    def push_packet(self, packet_dict: dict[str, Any]):
        with self._lock:
            self.live_packets.append(packet_dict)
        self._notify_listeners("packet", packet_dict)

    def push_alert(self, alert_dict: dict[str, Any]):
        with self._lock:
            self.live_alerts.append(alert_dict)
        self._notify_listeners("alert", alert_dict)

    def get_recent_packets(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.live_packets)[-limit:]

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.live_alerts)[-limit:]

    def subscribe(self, callback_fn):
        with self._lock:
            self._listeners.append(callback_fn)

    def _notify_listeners(self, event_type: str, data: dict[str, Any]):
        for listener in self._listeners:
            try:
                listener(event_type, data)
            except Exception:
                pass

realtime_bus = RealTimeEventBus()
