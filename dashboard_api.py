import sqlite3

DATABASE = "database/wishield.db"


def fetch_rows(cursor, query, params=()):
    cursor.execute(query, params)
    return [dict(row) for row in cursor.fetchall()]


def get_dashboard_data():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    devices = fetch_rows(cursor, """
        SELECT
            d.id,
            d.ip_address,
            d.mac_address,
            d.first_seen,
            d.last_seen,
            d.status,
            d.device_type,
            d.hostname,
            d.vendor,
            d.is_rogue,
            d.channel,
            d.rssi,
            COALESCE((
                SELECT ta.threat_score
                FROM threat_analysis ta
                WHERE ta.device_id = d.id
                ORDER BY ta.threat_id DESC
                LIMIT 1
            ), 0) AS threat_score,
            COALESCE((
                SELECT ta.risk_level
                FROM threat_analysis ta
                WHERE ta.device_id = d.id
                ORDER BY ta.threat_id DESC
                LIMIT 1
            ), 'LOW') AS risk_level
        FROM devices d
        ORDER BY d.last_seen DESC
    """)

    activity_logs = fetch_rows(cursor, """
        SELECT id, device_id, event_type, description, timestamp
        FROM activity_logs
        ORDER BY timestamp DESC
        LIMIT 500
    """)

    threat_analysis = fetch_rows(cursor, """
        SELECT
            threat_id,
            device_id,
            threat_score,
            risk_level,
            analyzed_at,
            threat_type,
            detection_source,
            confidence,
            evidence
        FROM threat_analysis
        ORDER BY analyzed_at DESC
        LIMIT 500
    """)

    alerts = fetch_rows(cursor, """
        SELECT
            id,
            device_id,
            alert_type,
            severity,
            threat_score,
            message,
            created_at,
            status,
            acknowledged_at,
            resolved_at,
            response_status
        FROM alerts
        ORDER BY created_at DESC
        LIMIT 500
    """)

    honeypot_interactions = fetch_rows(cursor, """
        SELECT
            id,
            device_id,
            interaction_type,
            source_ip,
            source_mac,
            target,
            protocol,
            details,
            timestamp
        FROM honeypot_interactions
        ORDER BY timestamp DESC
        LIMIT 500
    """)

    packet_captures = fetch_rows(cursor, """
        SELECT
            id,
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
        FROM packet_captures
        ORDER BY timestamp DESC
        LIMIT 500
    """)

    wireless_attacks = fetch_rows(cursor, """
        SELECT
            id,
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
        FROM wireless_attacks
        ORDER BY detected_at DESC
        LIMIT 500
    """)

    rf_metrics = fetch_rows(cursor, """
        SELECT
            id,
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
        FROM rf_metrics
        ORDER BY timestamp DESC
        LIMIT 500
    """)

    network_packet_activity = fetch_rows(cursor, """
        SELECT
            id,
            timestamp,
            packet_count,
            byte_count,
            packets_per_second,
            bytes_per_second,
            protocol,
            channel
        FROM network_packet_activity
        ORDER BY timestamp DESC
        LIMIT 500
    """)

    live_capture_events = fetch_rows(cursor, """
        SELECT
            id,
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
        FROM live_capture_events
        ORDER BY timestamp DESC
        LIMIT 500
    """)

    # Mapping threat_analysis data to threat_intelligence so frontend renders it correctly
    threat_intelligence = threat_analysis

    response_actions = fetch_rows(cursor, """
        SELECT
            id,
            device_id,
            alert_id,
            action_type,
            action_status,
            action_description,
            initiated_at,
            completed_at,
            result
        FROM response_actions
        ORDER BY initiated_at DESC
        LIMIT 500
    """)

    honeypot_status = fetch_rows(cursor, """
        SELECT
            id,
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
        FROM honeypot_status
        ORDER BY last_seen DESC
        LIMIT 20
    """)

    system_events = fetch_rows(cursor, """
        SELECT
            id,
            event_type,
            source,
            message,
            severity,
            timestamp,
            details
        FROM system_events
        ORDER BY timestamp DESC
        LIMIT 500
    """)

    connection.close()

    return {
        "devices": devices,
        "activity_logs": activity_logs,
        "threat_analysis": threat_analysis,
        "alerts": alerts,
        "honeypot_interactions": honeypot_interactions,
        "packet_captures": packet_captures,
        "wireless_attacks": wireless_attacks,
        "rf_metrics": rf_metrics,
        "network_packet_activity": network_packet_activity,
        "live_capture_events": live_capture_events,
        "threat_intelligence": threat_intelligence,
        "response_actions": response_actions,
        "honeypot_status": honeypot_status,
        "system_events": system_events,
    }