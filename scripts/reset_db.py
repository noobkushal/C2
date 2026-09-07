import argparse
import os
import shutil
import sqlite3
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database.database import init_db, get_db_connection
from src.utils.logging_config import logger

def reset_database(db_path: str = "data/netwatch.db", full: bool = False):
    """Wipes SQLite tables and optionally clears raw PCAP/Zeek files."""
    if os.path.exists(db_path):
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("DROP TABLE IF EXISTS network_events;")
            cursor.execute("DROP TABLE IF EXISTS dns_events;")
            cursor.execute("DROP TABLE IF EXISTS alerts;")
            cursor.execute("DROP TABLE IF EXISTS investigations;")
            cursor.execute("DROP TABLE IF EXISTS detection_rules;")
            conn.commit()
            logger.info(f"Database tables dropped from {db_path}")
        finally:
            conn.close()

    init_db(db_path)
    logger.info("Database schema re-initialized.")

    if full:
        print("Full reset requested. Cleaning raw PCAP files and Zeek log archives...")
        for folder in ["data/raw", "data/zeek", "data/alerts"]:
            if os.path.exists(folder):
                for item in os.listdir(folder):
                    if item == ".gitkeep":
                        continue
                    item_path = os.path.join(folder, item)
                    try:
                        if os.path.isfile(item_path):
                            os.remove(item_path)
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                    except Exception as e:
                        logger.warning(f"Failed to remove {item_path}: {e}")
        print("Data directories cleaned.")

def main():
    parser = argparse.ArgumentParser(description="Reset NetWatch SOC Database")
    parser.add_argument("--db-path", type=str, default="data/netwatch.db", help="Path to SQLite database")
    parser.add_argument("--full", action="store_true", help="Also wipe raw PCAPs, Zeek logs, and JSON evidence exports")

    args = parser.parse_args()
    reset_database(db_path=args.db_path, full=args.full)
    print("Database reset complete.")

if __name__ == "__main__":
    main()
