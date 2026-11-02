import sqlite3

connection = sqlite3.connect("database/wishield.db")
cursor = connection.cursor()

cursor.execute("""
SELECT
    id,
    device_id,
    alert_type,
    severity,
    threat_score,
    message,
    created_at,
    status
FROM alerts
ORDER BY created_at DESC
""")

alerts = cursor.fetchall()

print("\n--- SECURITY ALERTS ---")

for alert in alerts:
    print(alert)

connection.close()