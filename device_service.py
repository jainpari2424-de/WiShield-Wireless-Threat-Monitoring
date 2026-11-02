import sqlite3
from datetime import datetime

from activity_logger import log_activity
from threat_detection import calculate_threat


DATABASE = "database/wishield.db"


def save_device(ip_address, mac_address):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    mac_address = mac_address.strip().upper()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        SELECT id
        FROM devices
        WHERE mac_address = ?
    """, (mac_address,))

    device = cursor.fetchone()

    if device is None:

        cursor.execute("""
            INSERT INTO devices (
                ip_address,
                mac_address,
                first_seen,
                last_seen,
                status
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            ip_address,
            mac_address,
            now,
            now,
            "Connected"
        ))

        device_id = cursor.lastrowid

        print("New device added.")

        event_type = "CONNECT"

        description = (
            f"Device connected - "
            f"IP: {ip_address}, MAC: {mac_address}"
        )

    else:

        device_id = device[0]

        cursor.execute("""
            UPDATE devices
            SET
                ip_address = ?,
                last_seen = ?,
                status = ?
            WHERE id = ?
        """, (
            ip_address,
            now,
            "Connected",
            device_id
        ))

        print("Existing device updated.")

        event_type = "RECONNECT"

        description = (
            f"Device reconnected - "
            f"IP: {ip_address}, MAC: {mac_address}"
        )

    connection.commit()
    connection.close()

    # Activity log automatically create hoga
    log_activity(
        device_id,
        event_type,
        description
    )

    # Threat analysis automatically chalega
    calculate_threat(device_id)

    return device_id


def disconnect_device(mac_address):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    mac_address = mac_address.strip().upper()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        SELECT id, ip_address
        FROM devices
        WHERE mac_address = ?
    """, (mac_address,))

    device = cursor.fetchone()

    if device is None:

        connection.close()

        print("Device not found.")

        return None

    device_id = device[0]
    ip_address = device[1]

    cursor.execute("""
        UPDATE devices
        SET
            last_seen = ?,
            status = ?
        WHERE id = ?
    """, (
        now,
        "Disconnected",
        device_id
    ))

    connection.commit()
    connection.close()

    # Disconnect activity automatically log hoga
    log_activity(
        device_id,
        "DISCONNECT",
        f"Device disconnected - IP: {ip_address}, MAC: {mac_address}"
    )

    # Threat analysis automatically chalega
    calculate_threat(device_id)

    print("Device disconnected successfully.")

    return device_id