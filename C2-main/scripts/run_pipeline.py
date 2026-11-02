import argparse
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.services.pipeline import run_pipeline_on_zeek_dir, run_detection_only
from scripts.generate_test_data import generate_all_test_data
from src.utils.logging_config import logger

def main():
    parser = argparse.ArgumentParser(description="NetWatch SOC ETL & Detection Pipeline")
    parser.add_argument("--zeek-dir", type=str, help="Path to directory containing Zeek TSV logs")
    parser.add_argument("--sample", action="store_true", help="Generate synthetic sample dataset and run detection")
    parser.add_argument("--pcap-ref", type=str, default=None, help="Optional PCAP reference filename")
    parser.add_argument("--db-path", type=str, default=None, help="Custom SQLite database path")

    args = parser.parse_args()

    if args.sample:
        print("Generating synthetic sample dataset...")
        counts = generate_all_test_data(db_path=args.db_path)
        print(f"Generated {counts['net_events']} network events and {counts['dns_events']} DNS events.")
        print("Running detection engine on synthetic events...")
        alerts_count = run_detection_only(db_path=args.db_path)
        print(f"Pipeline complete. Generated/updated {alerts_count} alerts in database.")
    elif args.zeek_dir:
        if not os.path.exists(args.zeek_dir):
            print(f"Error: Zeek directory '{args.zeek_dir}' not found.", file=sys.stderr)
            sys.exit(1)
        print(f"Running pipeline on Zeek logs in '{args.zeek_dir}'...")
        res = run_pipeline_on_zeek_dir(args.zeek_dir, pcap_ref=args.pcap_ref, db_path=args.db_path)
        print(f"Pipeline complete.")
        print(f"  Network events parsed:  {res['network_events_parsed']}")
        print(f"  Network events inserted:{res['network_events_inserted']}")
        print(f"  DNS events parsed:      {res['dns_events_parsed']}")
        print(f"  DNS events inserted:    {res['dns_events_inserted']}")
        print(f"  Alerts generated:       {res['alerts_generated']}")
    else:
        print("No ingestion directory specified. Running detection engine on existing database records...")
        alerts_count = run_detection_only(db_path=args.db_path)
        print(f"Detection engine complete. {alerts_count} alerts generated/updated.")

if __name__ == "__main__":
    main()
