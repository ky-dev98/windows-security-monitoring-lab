import sqlite3

DB_PATH = r"C:\Users\vn55c\Desktop\log_monitor_lab\data\edr.db"


def print_rows(title, rows):
    print()
    print(f"=== {title} ===")

    if not rows:
        print("(no data)")
        return

    for row in rows:
        print(row)


def main():
    conn = sqlite3.connect(DB_PATH)

    try:
        # --------------------------------------------------
        # 1. Latest 10 Events
        # --------------------------------------------------
        rows = conn.execute("""
            SELECT
                id,
                timestamp,
                source,
                event_id,
                event_type,
                image,
                host,
                url
            FROM events
            ORDER BY id DESC
            LIMIT 10
        """).fetchall()

        print_rows(
            "Latest 10 events",
            rows
        )


        # --------------------------------------------------
        # 2. Event Count by Source
        # --------------------------------------------------
        rows = conn.execute("""
            SELECT
                source,
                COUNT(*)
            FROM events
            GROUP BY source
            ORDER BY COUNT(*) DESC
        """).fetchall()

        print_rows(
            "Event count by source",
            rows
        )


        # --------------------------------------------------
        # 3. Event Count by Sysmon Event ID
        # --------------------------------------------------
        rows = conn.execute("""
            SELECT
                event_id,
                event_type,
                COUNT(*)
            FROM events
            WHERE source = 'sysmon'
            GROUP BY event_id, event_type
            ORDER BY COUNT(*) DESC
        """).fetchall()

        print_rows(
            "Sysmon event count by Event ID",
            rows
        )


        # --------------------------------------------------
        # 4. Event ID 3 - Event Count by Process
        # --------------------------------------------------
        rows = conn.execute("""
            SELECT
                image,
                COUNT(*)
            FROM events
            WHERE source = 'sysmon'
              AND event_id = 3
            GROUP BY image
            ORDER BY COUNT(*) DESC
            LIMIT 20
        """).fetchall()

        print_rows(
            "Event ID 3 count by Image",
            rows
        )


        # --------------------------------------------------
        # 5. Event ID 3 - Event Count by Destination
        # --------------------------------------------------
        rows = conn.execute("""
            SELECT
                destination_ip,
                destination_port,
                protocol,
                COUNT(*)
            FROM events
            WHERE source = 'sysmon'
              AND event_id = 3
            GROUP BY
                destination_ip,
                destination_port,
                protocol
            ORDER BY COUNT(*) DESC
            LIMIT 20
        """).fetchall()

        print_rows(
            "Event ID 3 top destinations",
            rows
        )


        # --------------------------------------------------
        # 6. File Create (ID 11) - Event Count by Process
        # --------------------------------------------------
        rows = conn.execute("""
            SELECT
                image,
                COUNT(*)
            FROM events
            WHERE source = 'sysmon'
              AND event_id = 11
            GROUP BY image
            ORDER BY COUNT(*) DESC
            LIMIT 20
        """).fetchall()

        print_rows(
            "File Create count by Image",
            rows
        )


        # --------------------------------------------------
        # 7. File Delete (ID 23) - Event Count by Process
        # --------------------------------------------------
        rows = conn.execute("""
            SELECT
                image,
                COUNT(*)
            FROM events
            WHERE source = 'sysmon'
              AND event_id = 23
            GROUP BY image
            ORDER BY COUNT(*) DESC
            LIMIT 20
        """).fetchall()

        print_rows(
            "File Delete count by Image",
            rows
        )


        # --------------------------------------------------
        # 8. mitmproxy - Event Count by Host
        # --------------------------------------------------
        rows = conn.execute("""
            SELECT
                host,
                COUNT(*)
            FROM events
            WHERE source = 'mitmproxy'
            GROUP BY host
            ORDER BY COUNT(*) DESC
            LIMIT 20
        """).fetchall()

        print_rows(
            "mitmproxy count by Host",
            rows
        )

        print()
        print("=== events table columns ===")

        rows = conn.execute("""
            PRAGMA table_info(events)
        """).fetchall()

        for row in rows:
            print(row)

        print()
        print("=== Latest mitmproxy raw_data ===")

        row = conn.execute("""
            SELECT raw_data
            FROM events
            WHERE source = 'mitmproxy'
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()

        if row:
            print(row[0])


    except sqlite3.Error as e:
        print(f"[DB ERROR] {e}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
