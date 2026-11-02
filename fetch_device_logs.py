import sqlite3

connection = sqlite3.connect("database/wishield.db")
cursor = connection.cursor()

cursor.execute("""
SELECT
    devices.device_name,
    devices.ip_address,
    devices.mac_address,
    activity_logs.event_type,
    activity_logs.description,
    activity_logs.timestamp
FROM devices
JOIN activity_logs
ON devices.id = activity_logs.device_id
""")

logs = cursor.fetchall()

for log in logs:
    print(log)

connection.close()