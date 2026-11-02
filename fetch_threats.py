import sqlite3

connection = sqlite3.connect("database/wishield.db")
cursor = connection.cursor()

cursor.execute("""
SELECT
    threat_id,
    device_id,
    threat_score,
    risk_level,
    analyzed_at
FROM threat_analysis
ORDER BY analyzed_at DESC
""")

threats = cursor.fetchall()

print("\n--- THREAT ANALYSIS ---")

for threat in threats:
    print(threat)

connection.close()