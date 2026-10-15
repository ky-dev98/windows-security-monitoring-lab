import json
import os
import queue
import sqlite3
import threading
import time


PROXY_LOG_PATH = r"<PROJECT_PATH>\log_monitor_lab\logs\mitmproxy.jsonl"
DB_PATH = r"<PROJECT_PATH>\log_monitor_lab\data\edr.db"

DB_QUEUE = queue.Queue()

BATCH_SIZE = 50
BATCH_TIMEOUT = 2.0

POLL_INTERVAL = 0.2

event_count = 0


def get_connection():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=10
    )

    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=10000;")

    return conn


def init_db():
    conn = get_connection()

    # If there is no events table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_id INTEGER,
            event_type TEXT,

            process_guid TEXT,
            process_id TEXT,
            image TEXT,
            command_line TEXT,
            parent_image TEXT,

            destination_ip TEXT,
            destination_port TEXT,
            protocol TEXT,

            query_name TEXT,
            query_results TEXT,

            target_object TEXT,
            target_filename TEXT,
            details TEXT,
            referer TEXT,
            raw_data TEXT
        )
    """)

    # Proxy Columns
    required_columns = {
        "client_ip": "TEXT",
        "http_method": "TEXT",
        "scheme": "TEXT",
        "host": "TEXT",
        "url": "TEXT",
        "http_status": "INTEGER",
        "content_type": "TEXT",
        "user_agent": "TEXT",
        "referer": "TEXT"
    }

    current_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(events)")
    }

    for column_name, column_type in required_columns.items():
        if column_name not in current_columns:
            conn.execute(
                f"ALTER TABLE events "
                f"ADD COLUMN {column_name} {column_type}"
            )

    # Create index for searching URL/Host at the analysis
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_host
        ON events(host)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_url
        ON events(url)
    """)

    conn.commit()
    conn.close()


def prepare_proxy_row(data):
    return (
        data.get("timestamp"),
        "mitmproxy",
        0,
        "http",

        data.get("client_ip"),
        data.get("method"),
        data.get("scheme"),
        data.get("host"),
        data.get("url"),
        data.get("status_code"),
        data.get("content_type"),
        data.get("user_agent"),
        data.get("referer"),

        json.dumps(
            data,
            ensure_ascii=False
        )
    )


def db_writer():
    conn = get_connection()

    insert_sql = """
        INSERT INTO events (
            timestamp,
            source,
            event_id,
            event_type,

            client_ip,
            http_method,
            scheme,
            host,
            url,
            http_status,
            content_type,
            user_agent,
            referer,
            raw_data
        )
        VALUES (
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?
        )
    """

    batch = []

    while True:
        try:
            item = DB_QUEUE.get(
                timeout=BATCH_TIMEOUT
            )

            if item is None:
                break

            batch.append(item)

            if len(batch) < BATCH_SIZE:
                continue

        except queue.Empty:
            if not batch:
                continue

        try:
            conn.executemany(
                insert_sql,
                batch
            )

            conn.commit()

        except Exception as e:
            print(f"[DB ERROR] {e}")
            conn.rollback()

        finally:
            batch.clear()

    # Store events at the end of process
    if batch:
        try:
            conn.executemany(
                insert_sql,
                batch
            )

            conn.commit()

        except Exception as e:
            print(f"[DB ERROR] {e}")
            conn.rollback()

    conn.close()


def open_log():
    while not os.path.exists(PROXY_LOG_PATH):
        print("[INFO] Waiting for mitmproxy log...")
        time.sleep(1)

    f = open(
        PROXY_LOG_PATH,
        "r",
        encoding="utf-8"
    )

    # Skip existing logs when the collector starts
    f.seek(0, os.SEEK_END)

    return f


def process_proxy_line(line):
    global event_count

    try:
        data = json.loads(line)

        DB_QUEUE.put(
            prepare_proxy_row(data)
        )

        event_count += 1

        if event_count % 100 == 0:
            print(
                f"[INFO] Collected: {event_count} "
                f"| Queue: {DB_QUEUE.qsize()}"
            )

    except json.JSONDecodeError as e:
        print(
            f"[JSON ERROR] {e}"
        )
        

def proxy_log_reader():
    global event_count

    offset = 0

    print("[INFO] Proxy log reader started.")

    while True:
        try:
            # Wait until the file exists
            if not os.path.exists(PROXY_LOG_PATH):
                time.sleep(1)
                continue

            current_size = os.path.getsize(PROXY_LOG_PATH)

            # ----------------------------------------
            # Detect log lotate
            # The current file size is smaller than the previous offset.
            # ----------------------------------------
            if current_size < offset:

                rotated_file = PROXY_LOG_PATH + ".1"

                # If unread data remains from before rotation, read it from the .1 file.
                if os.path.exists(rotated_file):
                    try:
                        with open(
                            rotated_file,
                            "r",
                            encoding="utf-8"
                        ) as f:

                            f.seek(offset)

                            for line in f:
                                process_proxy_line(line)

                    except Exception as e:
                        print(
                            f"[ROTATION READ ERROR] {e}"
                        )

                # Read the new mitmproxy.jsonl file from the beginning
                offset = 0

                print(
                    "[INFO] Log rotation detected."
                )

            # ----------------------------------------
            # Read only data appended since the last offset. 
            # ----------------------------------------
            with open(
                PROXY_LOG_PATH,
                "r",
                encoding="utf-8"
            ) as f:

                f.seek(offset)

                while True:
                    line = f.readline()

                    if not line:
                        break

                    process_proxy_line(line)

                offset = f.tell()

            # Close file
            time.sleep(POLL_INTERVAL)

        except FileNotFoundError:
            time.sleep(POLL_INTERVAL)

        except Exception as e:
            print(
                f"[PROXY ERROR] {e}"
            )

            time.sleep(1)


def main():
    init_db()

    print("Mini EDR - Proxy Collector")
    print(f"Log      : {PROXY_LOG_PATH}")
    print(f"Database : {DB_PATH}")
    print(f"Batch    : {BATCH_SIZE}")
    print("Ctrl+C to stop.")
    print()

    writer_thread = threading.Thread(
        target=db_writer,
        name="ProxyDBWriter"
    )

    writer_thread.start()

    reader_thread = threading.Thread(
        target=proxy_log_reader,
        name="ProxyLogReader",
        daemon=True
    )

    reader_thread.start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping proxy collector...")

    finally:
        DB_QUEUE.put(None)

        writer_thread.join()

        print(
            f"Stopped. Total collected: "
            f"{event_count}"
        )


if __name__ == "__main__":
    main()
