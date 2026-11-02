from flask import Flask, jsonify, request, send_from_directory
import sqlite3
import os
from datetime import datetime

from device_service import save_device, disconnect_device
from dashboard_api import get_dashboard_data


app = Flask(__name__, static_folder=".", template_folder=".")

# Absolute path for SQLite DB to prevent path errors
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "database", "wishield.db")


# =========================================================
# DATABASE HELPER
# =========================================================

def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# =========================================================
# HOME / DASHBOARD ROUTES
# =========================================================

@app.route("/")
def home():
    return send_from_directory(".", "dashboard.html")


# =========================================================
# DEVICE CONNECT / RECONNECT
# =========================================================

@app.route("/device", methods=["POST"])
def add_device():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    ip_address = data.get("ip")
    mac_address = data.get("mac")

    if not ip_address or not mac_address:
        return jsonify({
            "success": False,
            "message": "IP and MAC are required"
        }), 400

    device_id = save_device(
        ip_address,
        mac_address
    )

    return jsonify({
        "success": True,
        "message": "Device data received",
        "data": device_id
    })


# =========================================================
# DEVICE DISCONNECT
# =========================================================

@app.route("/device/disconnect", methods=["POST"])
def remove_device():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    mac_address = data.get("mac")

    if not mac_address:
        return jsonify({
            "success": False,
            "message": "MAC address is required"
        }), 400

    device_id = disconnect_device(mac_address)

    if device_id is None:
        return jsonify({
            "success": False,
            "message": "Device not found"
        }), 404

    return jsonify({
        "success": True,
        "message": "Device disconnected",
        "data": device_id
    })


# =========================================================
# DASHBOARD DATA API
# =========================================================

@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    data = get_dashboard_data()
    return jsonify(data)


# =========================================================
# HONEYPOT INTERACTION
# =========================================================

@app.route("/api/honeypot/interaction", methods=["POST"])
def honeypot_interaction():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    timestamp = data.get(
        "timestamp",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    cursor.execute("""
        INSERT INTO honeypot_interactions (
            device_id,
            interaction_type,
            source_ip,
            source_mac,
            target,
            protocol,
            details,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("device_id"),
        data.get("interaction_type"),
        data.get("source_ip"),
        data.get("source_mac"),
        data.get("target"),
        data.get("protocol"),
        data.get("details"),
        timestamp
    ))

    connection.commit()
    interaction_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "success": True,
        "message": "Honeypot interaction stored",
        "interaction_id": interaction_id
    })


# =========================================================
# PACKET CAPTURE
# =========================================================

@app.route("/api/packet", methods=["POST"])
def packet_capture():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    timestamp = data.get(
        "timestamp",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    cursor.execute("""
        INSERT INTO packet_captures (
            device_id,
            timestamp,
            packet_type,
            protocol,
            source_ip,
            destination_ip,
            source_mac,
            destination_mac,
            source_port,
            destination_port,
            packet_size,
            channel,
            interface,
            capture_reference,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("device_id"),
        timestamp,
        data.get("packet_type"),
        data.get("protocol"),
        data.get("source_ip"),
        data.get("destination_ip"),
        data.get("source_mac"),
        data.get("destination_mac"),
        data.get("source_port"),
        data.get("destination_port"),
        data.get("packet_size"),
        data.get("channel"),
        data.get("interface"),
        data.get("capture_reference"),
        data.get("details")
    ))

    connection.commit()
    packet_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "success": True,
        "message": "Packet information stored",
        "packet_id": packet_id
    })


# =========================================================
# WIRELESS ATTACK
# =========================================================

@app.route("/api/wireless-attack", methods=["POST"])
def wireless_attack():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    detected_at = data.get(
        "detected_at",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    cursor.execute("""
        INSERT INTO wireless_attacks (
            device_id,
            attack_type,
            source_mac,
            target_mac,
            source_ip,
            target_ip,
            channel,
            packet_count,
            severity,
            threat_score,
            status,
            first_seen,
            last_seen,
            detected_at,
            evidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("device_id"),
        data.get("attack_type"),
        data.get("source_mac"),
        data.get("target_mac"),
        data.get("source_ip"),
        data.get("target_ip"),
        data.get("channel"),
        data.get("packet_count", 0),
        data.get("severity"),
        data.get("threat_score", 0),
        data.get("status", "Active"),
        data.get("first_seen", detected_at),
        data.get("last_seen", detected_at),
        detected_at,
        data.get("evidence")
    ))

    connection.commit()
    attack_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "success": True,
        "message": "Wireless attack stored",
        "attack_id": attack_id
    })


# =========================================================
# RF METRICS
# =========================================================

@app.route("/api/rf", methods=["POST"])
def rf_metrics():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    timestamp = data.get(
        "timestamp",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    cursor.execute("""
        INSERT INTO rf_metrics (
            timestamp,
            channel,
            frequency_mhz,
            rssi,
            signal_strength,
            noise_level,
            channel_activity,
            utilization,
            bandwidth,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        data.get("channel"),
        data.get("frequency_mhz"),
        data.get("rssi"),
        data.get("signal_strength"),
        data.get("noise_level"),
        data.get("channel_activity"),
        data.get("utilization"),
        data.get("bandwidth"),
        data.get("details")
    ))

    connection.commit()
    rf_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "success": True,
        "message": "RF metrics stored",
        "rf_id": rf_id
    })


# =========================================================
# NETWORK PACKET ACTIVITY
# =========================================================

@app.route("/api/network/activity", methods=["POST"])
def network_activity():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    timestamp = data.get(
        "timestamp",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    cursor.execute("""
        INSERT INTO network_packet_activity (
            timestamp,
            packet_count,
            byte_count,
            packets_per_second,
            bytes_per_second,
            protocol,
            channel
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        data.get("packet_count", 0),
        data.get("byte_count", 0),
        data.get("packets_per_second", 0),
        data.get("bytes_per_second", 0),
        data.get("protocol"),
        data.get("channel")
    ))

    connection.commit()
    activity_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "success": True,
        "message": "Network activity stored",
        "activity_id": activity_id
    })


# =========================================================
# LIVE CAPTURE EVENT
# =========================================================

@app.route("/api/live-capture", methods=["POST"])
def live_capture():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    timestamp = data.get(
        "timestamp",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    cursor.execute("""
        INSERT INTO live_capture_events (
            device_id,
            event_type,
            packet_type,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            channel,
            rssi,
            packet_size,
            timestamp,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("device_id"),
        data.get("event_type"),
        data.get("packet_type"),
        data.get("source_mac"),
        data.get("destination_mac"),
        data.get("source_ip"),
        data.get("destination_ip"),
        data.get("channel"),
        data.get("rssi"),
        data.get("packet_size"),
        timestamp,
        data.get("details")
    ))

    connection.commit()
    event_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "success": True,
        "message": "Live capture event stored",
        "event_id": event_id
    })


# =========================================================
# THREAT INTELLIGENCE (GET & POST)
# =========================================================

@app.route("/api/threat-intelligence", methods=["GET", "POST"])
def threat_intelligence():
    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "GET":
        cursor.execute("SELECT * FROM threat_intelligence ORDER BY detected_at DESC")
        rows = cursor.fetchall()
        connection.close()
        return jsonify([dict(row) for row in rows])

    data = request.get_json()

    if not data:
        connection.close()
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    detected_at = data.get(
        "detected_at",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    cursor.execute("""
        INSERT INTO threat_intelligence (
            device_id,
            threat_type,
            classification,
            severity,
            confidence,
            source,
            indicator,
            description,
            recommended_action,
            detected_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("device_id"),
        data.get("threat_type"),
        data.get("classification"),
        data.get("severity"),
        data.get("confidence"),
        data.get("source"),
        data.get("indicator"),
        data.get("description"),
        data.get("recommended_action"),
        detected_at
    ))

    connection.commit()
    intelligence_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "success": True,
        "message": "Threat intelligence stored",
        "intelligence_id": intelligence_id
    })


# =========================================================
# RESPONSE ACTION
# =========================================================

@app.route("/api/response", methods=["POST"])
def response_action():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    initiated_at = data.get(
        "initiated_at",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    cursor.execute("""
        INSERT INTO response_actions (
            device_id,
            alert_id,
            action_type,
            action_status,
            action_description,
            initiated_at,
            completed_at,
            result
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("device_id"),
        data.get("alert_id"),
        data.get("action_type"),
        data.get("action_status"),
        data.get("action_description"),
        initiated_at,
        data.get("completed_at"),
        data.get("result")
    ))

    connection.commit()
    response_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "success": True,
        "message": "Response action stored",
        "response_id": response_id
    })


# =========================================================
# HONEYPOT STATUS
# =========================================================

@app.route("/api/honeypot/status", methods=["POST"])
def honeypot_status():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No JSON data received"
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    last_seen = data.get(
        "last_seen",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    cursor.execute("""
        INSERT INTO honeypot_status (
            device_name,
            device_mac,
            ip_address,
            status,
            firmware_version,
            channel,
            rssi,
            last_seen,
            uptime_seconds,
            temperature,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("device_name"),
        data.get("device_mac"),
        data.get("ip_address"),
        data.get("status"),
        data.get("firmware_version"),
        data.get("channel"),
        data.get("rssi"),
        last_seen,
        data.get("uptime_seconds"),
        data.get("temperature"),
        data.get("details")
    ))

    connection.commit()
    status_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "success": True,
        "message": "Honeypot status stored",
        "status_id": status_id
    })


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )