import os
import tempfile
import pytest
from src.ingestion.zeek_parser import parse_zeek_log, map_conn_row, map_dns_row, map_http_row, map_ssl_row
from src.ingestion.pcap_processor import process_pcap_with_zeek, ZeekNotAvailableError

def test_parse_well_formed_conn_log():
    sample_conn = (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\n"
        "1711920000.000000\tC12345\t192.168.1.10\t49152\t10.0.0.1\t80\ttcp\thttp\t1.500000\t500\t1200\tSF\r\n"
    )
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
        f.write(sample_conn)
        f_path = f.name

    try:
        rows = list(parse_zeek_log(f_path))
        assert len(rows) == 1
        row = rows[0]
        assert row["id.orig_h"] == "192.168.1.10"
        assert row["id.resp_p"] == "80"
        assert row["iso_timestamp"] == "2024-03-31T21:20:00Z"

        event = map_conn_row(row, pcap_reference="test.pcap")
        assert event is not None
        assert event.source_ip == "192.168.1.10"
        assert event.destination_port == 80
        assert event.bytes_sent == 500
        assert event.bytes_received == 1200
        assert event.connection_state == "SF"
        assert event.pcap_reference == "test.pcap"
    finally:
        os.remove(f_path)

def test_parse_missing_optional_fields_and_sentinels():
    sample = (
        "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\n"
        "1711920000.0\t192.168.1.5\t1234\t10.0.0.2\t443\ttcp\t-\t(empty)\t-\n"
    )
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
        f.write(sample)
        f_path = f.name

    try:
        rows = list(parse_zeek_log(f_path))
        assert len(rows) == 1
        event = map_conn_row(rows[0])
        assert event is not None
        assert event.duration is None
        assert event.bytes_sent == 0
        assert event.bytes_received == 0
    finally:
        os.remove(f_path)

def test_parse_empty_file():
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
        f_path = f.name

    try:
        rows = list(parse_zeek_log(f_path))
        assert len(rows) == 0
    finally:
        os.remove(f_path)

def test_parse_malformed_row():
    sample = (
        "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\n"
        "1711920000.0\t192.168.1.5\t1234\t10.0.0.2\n"  # missing 5th field
        "1711920005.0\t192.168.1.5\t1234\t10.0.0.2\t80\n"
    )
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
        f.write(sample)
        f_path = f.name

    try:
        rows = list(parse_zeek_log(f_path))
        assert len(rows) == 1
        assert rows[0]["id.resp_p"] == "80"
    finally:
        os.remove(f_path)

def test_parse_non_numeric_timestamp():
    sample = (
        "#fields\tts\tid.orig_h\tid.resp_h\n"
        "invalid_time\t192.168.1.5\t10.0.0.2\n"
    )
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
        f.write(sample)
        f_path = f.name

    try:
        rows = list(parse_zeek_log(f_path))
        assert len(rows) == 0
    finally:
        os.remove(f_path)

def test_pcap_processor_nonexistent():
    with pytest.raises(FileNotFoundError):
        process_pcap_with_zeek("nonexistent_file.pcap")

def test_pcap_processor_invalid_ext():
    with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as f:
        f_path = f.name

    try:
        with pytest.raises(ValueError):
            process_pcap_with_zeek(f_path)
    finally:
        os.remove(f_path)
