import sqlite3

connection = sqlite3.connect("database/wishield.db")
cursor = connection.cursor()

# Remove duplicate devices and old test data
cursor.execute("DELETE FROM activity_logs")
cursor.execute("DELETE FROM threat_analysis")
cursor.execute("DELETE FROM alerts")
cursor.execute("DELETE FROM devices")

connection.commit()

print("Old test data cleaned successfully!")

connection.close()