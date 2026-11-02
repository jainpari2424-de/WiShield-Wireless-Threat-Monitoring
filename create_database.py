import sqlite3
import os


# =========================================================
# WiShield Database Configuration
# =========================================================

DATABASE = "database/wishield.db"

os.makedirs("database", exist_ok=True)


# =========================================================
# Connect to Database
# =========================================================

connection = sqlite3.connect(DATABASE)
cursor = connection.cursor()


# =========================================================
# Helper Function
# Adds a column only if it does not already exist
# This prevents breaking the existing database.
# =========================================================

def add_column_if_missing(table_name, column_name, column_definition):

    cursor.execute(f"PRAGMA table_info({table_name})")

    existing_columns = [
        row[1]
        for row in cursor.fetchall()
    ]

    if column_name not in existing_columns:

        cursor.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name} {column_definition}
            """
        )


# =========================================================
# 1. DEVICES
# Existing device monitoring table
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS devices (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    ip_address TEXT,

    mac_address TEXT UNIQUE,

    first_seen DATETIME,

    last_seen DATETIME,

    status TEXT,

    device_type TEXT,

    hostname TEXT,

    vendor TEXT,

    is_rogue INTEGER DEFAULT 0,

    channel INTEGER,

    rssi INTEGER
)
""")


# Add new columns if an older devices table already exists

add_column_if_missing(
    "devices",
    "device_type",
    "TEXT"
)

add_column_if_missing(
    "devices",
    "hostname",
    "TEXT"
)

add_column_if_missing(
    "devices",
    "vendor",
    "TEXT"
)

add_column_if_missing(
    "devices",
    "is_rogue",
    "INTEGER DEFAULT 0"
)

add_column_if_missing(
    "devices",
    "channel",
    "INTEGER"
)

add_column_if_missing(
    "devices",
    "rssi",
    "INTEGER"
)


# =========================================================
# 2. ACTIVITY LOGS
# CONNECT / RECONNECT / DISCONNECT etc.
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS activity_logs (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_id INTEGER,

    event_type TEXT,

    description TEXT,

    timestamp DATETIME,

    FOREIGN KEY (device_id)
        REFERENCES devices(id)
)
""")


# =========================================================
# 3. THREAT ANALYSIS
# Existing threat scoring system
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS threat_analysis (

    threat_id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_id INTEGER NOT NULL,

    threat_score INTEGER DEFAULT 0,

    risk_level TEXT,

    analyzed_at DATETIME,

    threat_type TEXT,

    detection_source TEXT,

    confidence REAL,

    evidence TEXT,

    FOREIGN KEY (device_id)
        REFERENCES devices(id)
)
""")


# Add new columns if older table exists

add_column_if_missing(
    "threat_analysis",
    "threat_type",
    "TEXT"
)

add_column_if_missing(
    "threat_analysis",
    "detection_source",
    "TEXT"
)

add_column_if_missing(
    "threat_analysis",
    "confidence",
    "REAL"
)

add_column_if_missing(
    "threat_analysis",
    "evidence",
    "TEXT"
)


# =========================================================
# 4. SECURITY ALERTS
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_id INTEGER,

    alert_type TEXT,

    severity TEXT,

    threat_score INTEGER,

    message TEXT,

    created_at DATETIME,

    status TEXT,

    acknowledged_at DATETIME,

    resolved_at DATETIME,

    response_status TEXT,

    FOREIGN KEY (device_id)
        REFERENCES devices(id)
)
""")


add_column_if_missing(
    "alerts",
    "acknowledged_at",
    "DATETIME"
)

add_column_if_missing(
    "alerts",
    "resolved_at",
    "DATETIME"
)

add_column_if_missing(
    "alerts",
    "response_status",
    "TEXT"
)


# =========================================================
# 5. HONEYPOT INTERACTIONS
# Stores interaction between wireless devices and honeypot
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS honeypot_interactions (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_id INTEGER,

    interaction_type TEXT,

    source_ip TEXT,

    source_mac TEXT,

    target TEXT,

    protocol TEXT,

    details TEXT,

    timestamp DATETIME,

    FOREIGN KEY (device_id)
        REFERENCES devices(id)
)
""")


# =========================================================
# 6. PACKET CAPTURES
# Stores packet metadata.
# Actual PCAP files should be stored separately.
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS packet_captures (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_id INTEGER,

    timestamp DATETIME,

    packet_type TEXT,

    protocol TEXT,

    source_ip TEXT,

    destination_ip TEXT,

    source_mac TEXT,

    destination_mac TEXT,

    source_port INTEGER,

    destination_port INTEGER,

    packet_size INTEGER,

    channel INTEGER,

    interface TEXT,

    capture_reference TEXT,

    details TEXT,

    FOREIGN KEY (device_id)
        REFERENCES devices(id)
)
""")


# =========================================================
# 7. WIRELESS ATTACKS
# Deauth / Probe / other wireless attack information
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS wireless_attacks (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_id INTEGER,

    attack_type TEXT,

    source_mac TEXT,

    target_mac TEXT,

    source_ip TEXT,

    target_ip TEXT,

    channel INTEGER,

    packet_count INTEGER DEFAULT 0,

    severity TEXT,

    threat_score INTEGER DEFAULT 0,

    status TEXT,

    first_seen DATETIME,

    last_seen DATETIME,

    detected_at DATETIME,

    evidence TEXT,

    FOREIGN KEY (device_id)
        REFERENCES devices(id)
)
""")


# =========================================================
# 8. RF / RADIO FREQUENCY METRICS
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS rf_metrics (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp DATETIME,

    channel INTEGER,

    frequency_mhz REAL,

    rssi INTEGER,

    signal_strength INTEGER,

    noise_level INTEGER,

    channel_activity REAL,

    utilization REAL,

    bandwidth REAL,

    details TEXT
)
""")


# =========================================================
# 9. NETWORK PACKET ACTIVITY
# Used for real-time packet graphs
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS network_packet_activity (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp DATETIME,

    packet_count INTEGER DEFAULT 0,

    byte_count INTEGER DEFAULT 0,

    packets_per_second REAL DEFAULT 0,

    bytes_per_second REAL DEFAULT 0,

    protocol TEXT,

    channel INTEGER
)
""")


# =========================================================
# 10. LIVE CAPTURE EVENTS
# Used by live packet/capture feed
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS live_capture_events (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_id INTEGER,

    event_type TEXT,

    packet_type TEXT,

    source_mac TEXT,

    destination_mac TEXT,

    source_ip TEXT,

    destination_ip TEXT,

    channel INTEGER,

    rssi INTEGER,

    packet_size INTEGER,

    timestamp DATETIME,

    details TEXT,

    FOREIGN KEY (device_id)
        REFERENCES devices(id)
)
""")


# =========================================================
# 11. THREAT INTELLIGENCE
# Classification and evidence information
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS threat_intelligence (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_id INTEGER,

    threat_type TEXT,

    classification TEXT,

    severity TEXT,

    confidence REAL,

    source TEXT,

    indicator TEXT,

    description TEXT,

    recommended_action TEXT,

    detected_at DATETIME,

    FOREIGN KEY (device_id)
        REFERENCES devices(id)
)
""")


# =========================================================
# 12. RESPONSE / MITIGATION ACTIONS
# Stores defensive response actions
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS response_actions (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_id INTEGER,

    alert_id INTEGER,

    action_type TEXT,

    action_status TEXT,

    action_description TEXT,

    initiated_at DATETIME,

    completed_at DATETIME,

    result TEXT,

    FOREIGN KEY (device_id)
        REFERENCES devices(id),

    FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
)
""")


# =========================================================
# 13. HONEYPOT STATUS
# Stores ESP8266 / honeypot status
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS honeypot_status (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_name TEXT,

    device_mac TEXT,

    ip_address TEXT,

    status TEXT,

    firmware_version TEXT,

    channel INTEGER,

    rssi INTEGER,

    last_seen DATETIME,

    uptime_seconds INTEGER,

    temperature REAL,

    details TEXT
)
""")


# =========================================================
# 14. SYSTEM EVENTS
# General WiShield / ESP system events
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS system_events (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    event_type TEXT,

    source TEXT,

    message TEXT,

    severity TEXT,

    timestamp DATETIME,

    details TEXT
)
""")


# =========================================================
# Create Useful Indexes
# Improves dashboard/API query performance
# =========================================================

cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_activity_device
ON activity_logs(device_id)
""")

cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_activity_timestamp
ON activity_logs(timestamp)
""")

cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_threat_device
ON threat_analysis(device_id)
""")

cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_threat_time
ON threat_analysis(analyzed_at)
""")

cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_alert_status
ON alerts(status)
""")

cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_alert_created
ON alerts(created_at)
""")

cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_packet_timestamp
ON packet_captures(timestamp)
""")

cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_attack_timestamp
ON wireless_attacks(detected_at)
""")

cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_rf_timestamp
ON rf_metrics(timestamp)
""")

cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_live_capture_timestamp
ON live_capture_events(timestamp)
""")


# =========================================================
# Save Changes
# =========================================================

connection.commit()


# =========================================================
# Show Created Tables
# =========================================================

cursor.execute("""
SELECT name
FROM sqlite_master
WHERE type = 'table'
ORDER BY name
""")

tables = cursor.fetchall()


print("\n==========================================")
print("WiShield Database Ready")
print("==========================================")

print("\nTables:")

for table in tables:
    print(" -", table[0])

print("\nDatabase:", DATABASE)

print("\n==========================================")
print("Database setup completed successfully!")
print("==========================================\n")


connection.close()