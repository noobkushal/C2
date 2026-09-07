from dataclasses import dataclass, field, asdict
import json
import uuid
from src.utils.time_utils import current_iso8601

@dataclass
class NetworkEvent:
    source_ip: str
    destination_ip: str
    log_source: str
    timestamp: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    domain: str | None = None
    duration: float | None = None
    bytes_sent: int = 0
    bytes_received: int = 0
    connection_state: str | None = None
    pcap_reference: str | None = None
    created_at: str = field(default_factory=current_iso8601)

    def to_row(self) -> tuple:
        return (
            self.event_id,
            self.timestamp,
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
            self.protocol,
            self.domain,
            self.duration,
            self.bytes_sent,
            self.bytes_received,
            self.connection_state,
            self.log_source,
            self.pcap_reference,
            self.created_at,
        )

    @classmethod
    def from_row(cls, row: tuple | dict) -> "NetworkEvent":
        if isinstance(row, dict):
            return cls(**row)
        return cls(
            event_id=row[0],
            timestamp=row[1],
            source_ip=row[2],
            source_port=row[3],
            destination_ip=row[4],
            destination_port=row[5],
            protocol=row[6],
            domain=row[7],
            duration=row[8],
            bytes_sent=row[9] if row[9] is not None else 0,
            bytes_received=row[10] if row[10] is not None else 0,
            connection_state=row[11],
            log_source=row[12],
            pcap_reference=row[13],
            created_at=row[14],
        )

@dataclass
class DNSEvent:
    source_ip: str
    domain: str
    timestamp: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    query_type: str | None = None
    response: str | None = None
    ttl: float | None = None
    created_at: str = field(default_factory=current_iso8601)

    def to_row(self) -> tuple:
        return (
            self.event_id,
            self.timestamp,
            self.source_ip,
            self.domain,
            self.query_type,
            self.response,
            self.ttl,
            self.created_at,
        )

    @classmethod
    def from_row(cls, row: tuple | dict) -> "DNSEvent":
        if isinstance(row, dict):
            return cls(**row)
        return cls(
            event_id=row[0],
            timestamp=row[1],
            source_ip=row[2],
            domain=row[3],
            query_type=row[4],
            response=row[5],
            ttl=row[6],
            created_at=row[7],
        )

@dataclass
class Alert:
    source_ip: str
    destination_ip: str
    alert_type: str
    severity: str
    confidence: float
    risk_score: int
    reason: str
    first_seen: str
    last_seen: str
    timestamp: str = field(default_factory=current_iso8601)
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    destination_port: int | None = None
    evidence: str = "{}"
    status: str = "NEW"
    created_at: str = field(default_factory=current_iso8601)
    updated_at: str = field(default_factory=current_iso8601)

    def to_row(self) -> tuple:
        return (
            self.alert_id,
            self.timestamp,
            self.source_ip,
            self.destination_ip,
            self.destination_port,
            self.alert_type,
            self.severity,
            self.confidence,
            self.risk_score,
            self.reason,
            self.evidence,
            self.status,
            self.first_seen,
            self.last_seen,
            self.created_at,
            self.updated_at,
        )

    @classmethod
    def from_row(cls, row: tuple | dict) -> "Alert":
        if isinstance(row, dict):
            return cls(**row)
        return cls(
            alert_id=row[0],
            timestamp=row[1],
            source_ip=row[2],
            destination_ip=row[3],
            destination_port=row[4],
            alert_type=row[5],
            severity=row[6],
            confidence=row[7],
            risk_score=row[8],
            reason=row[9],
            evidence=row[10],
            status=row[11],
            first_seen=row[12],
            last_seen=row[13],
            created_at=row[14],
            updated_at=row[15],
        )

@dataclass
class Investigation:
    alert_id: str
    investigation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    analyst_status: str | None = None
    verdict: str | None = None
    notes: str | None = None
    created_at: str = field(default_factory=current_iso8601)
    updated_at: str = field(default_factory=current_iso8601)

    def to_row(self) -> tuple:
        return (
            self.investigation_id,
            self.alert_id,
            self.analyst_status,
            self.verdict,
            self.notes,
            self.created_at,
            self.updated_at,
        )

    @classmethod
    def from_row(cls, row: tuple | dict) -> "Investigation":
        if isinstance(row, dict):
            return cls(**row)
        return cls(
            investigation_id=row[0],
            alert_id=row[1],
            analyst_status=row[2],
            verdict=row[3],
            notes=row[4],
            created_at=row[5],
            updated_at=row[6],
        )

@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str | None = None
    enabled: int = 1
    severity: str | None = None
    threshold: float | None = None
    configuration: str | None = "{}"
    created_at: str = field(default_factory=current_iso8601)
    updated_at: str = field(default_factory=current_iso8601)

    def to_row(self) -> tuple:
        return (
            self.rule_id,
            self.name,
            self.description,
            self.enabled,
            self.severity,
            self.threshold,
            self.configuration,
            self.created_at,
            self.updated_at,
        )

    @classmethod
    def from_row(cls, row: tuple | dict) -> "DetectionRule":
        if isinstance(row, dict):
            return cls(**row)
        return cls(
            rule_id=row[0],
            name=row[1],
            description=row[2],
            enabled=row[3],
            severity=row[4],
            threshold=row[5],
            configuration=row[6],
            created_at=row[7],
            updated_at=row[8],
        )
