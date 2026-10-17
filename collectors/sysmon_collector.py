import time
import xml.etree.ElementTree as ET
import win32evtlog
import sqlite3
import json
import queue
import threading

DB_PATH = r"<PROJECT_PATH>\log_monitor_lab\data\edr.db"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"

DB_QUEUE = queue.Queue()

BATCH_SIZE = 50
BATCH_TIMEOUT = 2.0

TARGET_EVENT_IDS = {
    1,          # Process Create
    3,          # Network Connection
    11,         # File Create
    12, 13, 14, # Registry
    22,         # DNS Query
    23, 26      # File Delete
}

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}

EDR_DATA_DIR = r"<PROJECT_PATH>\log_monitor_lab\data".lower()

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


def should_ignore_event(event):
    data = event["data"]

    target = data.get("TargetFilename", "")

    if target.lower().startswith(EDR_DATA_DIR):
        return True

    return False

def prepare_db_row(event):
    data = event["data"]

    return (
        event["timestamp"],
        "sysmon",
        event["event_id"],
        get_event_type(event["event_id"]),

        data.get("ProcessGuid"),
        data.get("ProcessId"),
        data.get("Image"),
        data.get("CommandLine"),
        data.get("ParentImage"),

        data.get("DestinationIp"),
        data.get("DestinationPort"),
        data.get("Protocol"),

        data.get("QueryName"),
        data.get("QueryResults"),

        data.get("TargetObject"),
        data.get("TargetFilename"),
        data.get("Details"),

        json.dumps(data, ensure_ascii=False)
    )


def db_writer():
    conn = get_connection()

    # Improve SQLite write performance
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")

    insert_sql = """
        INSERT INTO events (
            timestamp,
            source,
            event_id,
            event_type,

            process_guid,
            process_id,
            image,
            command_line,
            parent_image,

            destination_ip,
            destination_port,
            protocol,

            query_name,
            query_results,

            target_object,
            target_filename,
            details,

            raw_data
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    batch = []

    while True:
        try:
            item = DB_QUEUE.get(timeout=BATCH_TIMEOUT)

            # Shutdown signal
            if item is None:
                break

            batch.append(item)

            # Wait until 50 records are accumulated
            if len(batch) < BATCH_SIZE:
                continue

        except queue.Empty:
            # If no events are received for 2 seconds.
            if not batch:
                continue

        try:
            conn.executemany(insert_sql, batch)
            conn.commit()

        except Exception as e:
            print(f"[DB ERROR] {e}")
            conn.rollback()

        finally:
            batch.clear()

    # Write any remaining data in the queue before shutdown
    if batch:
        try:
            conn.executemany(insert_sql, batch)
            conn.commit()

        except Exception as e:
            print(f"[DB ERROR] {e}")
            conn.rollback()

    conn.close()


def init_db():
    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,

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

            raw_data TEXT
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON events(timestamp)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_event_type
        ON events(event_type)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_process_guid
        ON events(process_guid)
    """)

    conn.commit()
    conn.close()

def get_event_type(event_id):
    mapping = {
        1: "process_create",
        3: "network_connection",
        11: "file_create",

        12: "registry_create_delete",
        13: "registry_value_set",
        14: "registry_rename",

        22: "dns_query",

        23: "file_delete",
        26: "file_delete_detected"
    }

    return mapping.get(event_id, "unknown")


def parse_event(xml_text):
    root = ET.fromstring(xml_text)

    system = root.find("e:System", NS)

    event_id = int(system.find("e:EventID", NS).text)

    time_created = system.find("e:TimeCreated", NS)
    timestamp = time_created.attrib.get("SystemTime")

    event_data = {}

    data_root = root.find("e:EventData", NS)

    if data_root is not None:
        for item in data_root.findall("e:Data", NS):
            name = item.attrib.get("Name")

            if name:
                event_data[name] = item.text

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "data": event_data
    }


def print_event(event):
    event_id = event["event_id"]
    data = event["data"]

    print("-" * 80)
    print(f"Time     : {event['timestamp']}")
    print(f"Event ID : {event_id}")

    if event_id == 1:
        print("[Process Create]")
        print(f"Image       : {data.get('Image')}")
        print(f"ProcessId   : {data.get('ProcessId')}")
        print(f"ProcessGuid : {data.get('ProcessGuid')}")
        print(f"CommandLine : {data.get('CommandLine')}")
        print(f"ParentImage : {data.get('ParentImage')}")

    elif event_id == 3:
        print("[Network Connection]")
        print(f"Image           : {data.get('Image')}")
        print(f"ProcessId       : {data.get('ProcessId')}")
        print(f"ProcessGuid     : {data.get('ProcessGuid')}")
        print(f"DestinationIp   : {data.get('DestinationIp')}")
        print(f"DestinationPort : {data.get('DestinationPort')}")
        print(f"Protocol        : {data.get('Protocol')}")

    elif event_id == 22:
        print("[DNS Query]")
        print(f"Image        : {data.get('Image')}")
        print(f"ProcessId    : {data.get('ProcessId')}")
        print(f"ProcessGuid  : {data.get('ProcessGuid')}")
        print(f"QueryName    : {data.get('QueryName')}")
        print(f"QueryResults : {data.get('QueryResults')}")

    elif event_id == 11:
        print("[File Create]")
        print(f"Image          : {data.get('Image')}")
        print(f"ProcessId      : {data.get('ProcessId')}")
        print(f"ProcessGuid    : {data.get('ProcessGuid')}")
        print(f"TargetFilename : {data.get('TargetFilename')}")

    elif event_id in (12, 13, 14):
        print("[Registry Event]")
        print(f"EventType   : {data.get('EventType')}")
        print(f"Image       : {data.get('Image')}")
        print(f"ProcessId   : {data.get('ProcessId')}")
        print(f"ProcessGuid : {data.get('ProcessGuid')}")
        print(f"TargetObject: {data.get('TargetObject')}")
        print(f"Details     : {data.get('Details')}")

    elif event_id in (23, 26):
        print("[File Delete]")
        print(f"Image          : {data.get('Image')}")
        print(f"ProcessId      : {data.get('ProcessId')}")
        print(f"ProcessGuid    : {data.get('ProcessGuid')}")
        print(f"TargetFilename : {data.get('TargetFilename')}")

def callback(action, context, event_handle):
    global event_count

    try:
        if action != win32evtlog.EvtSubscribeActionDeliver:
            return 0

        xml_text = win32evtlog.EvtRender(
            event_handle,
            win32evtlog.EvtRenderEventXml
        )

        event = parse_event(xml_text)

        if event["event_id"] not in TARGET_EVENT_IDS:
            return 0

        if should_ignore_event(event):
            return 0

        DB_QUEUE.put(prepare_db_row(event))

        event_count += 1

        if event_count % 100 == 0:
            print(
                f"[INFO] Collected: {event_count} "
                f"| Queue: {DB_QUEUE.qsize()}"
            )

    except Exception as e:
        print(f"[ERROR] {e}")

    return 0


def main():
    global event_count

    init_db()

    print("Mini EDR Collector started")
    print(f"Database : {DB_PATH}")
    print(f"Events   : {sorted(TARGET_EVENT_IDS)}")
    print(f"Batch    : {BATCH_SIZE}")
    print("Ctrl+C to stop.")
    print()

    # Start the DB Writer in the background
    writer_thread = threading.Thread(
        target=db_writer,
        name="DBWriter"
    )

    writer_thread.start()

    query = (
        "*[System[("
        "EventID=1 or "
        "EventID=3 or "
        "EventID=11 or "
        "EventID=12 or "
        "EventID=13 or "
        "EventID=14 or "
        "EventID=22 or "
        "EventID=23 or "
        "EventID=26"
        ")]]"
    )

    subscription = win32evtlog.EvtSubscribe(
        CHANNEL,
        win32evtlog.EvtSubscribeToFutureEvents,
        None,
        callback,
        None,
        query
    )

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping collector...")

    finally:
        subscription.Close()

        # Signal the DB Writer to shutdown
        DB_QUEUE.put(None)

        # Wait for the DB writer to finish processing
        writer_thread.join()

        print(
            f"Stopped. Total collected: {event_count}"
        )

if __name__ == "__main__":
    main()
