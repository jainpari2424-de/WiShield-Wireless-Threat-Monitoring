import sqlite3
from datetime import datetime

DATABASE = "database/wishield.db"


def log_activity(device_id, event_type, description):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO activity_logs (
            device_id,
            event_type,
            description,
            timestamp
        )
        VALUES (?, ?, ?, ?)
    """, (
        device_id,
        event_type,
        description,
        timestamp
    ))

    connection.commit()
    connection.close()

    print("Activity logged successfully.")