import sqlite3
from datetime import datetime

DATABASE = "database/wishield.db"


def generate_alert(device_id, threat_score, risk_level):

    if threat_score <= 50:
        return

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE device_id = ?
        AND status = 'Active'
    """, (device_id,))

    existing_alert = cursor.fetchone()

    if existing_alert:
        connection.close()
        return

    alert_type = "HIGH_THREAT"
    severity = "HIGH"

    message = (
        f"High threat device detected. "
        f"Threat score: {threat_score}"
    )

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO alerts (
            device_id,
            alert_type,
            severity,
            threat_score,
            message,
            created_at,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        device_id,
        alert_type,
        severity,
        threat_score,
        message,
        created_at,
        "Active"
    ))

    connection.commit()
    connection.close()

    print("🚨 Security Alert Generated!")