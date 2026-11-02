import sqlite3

connection = sqlite3.connect("database/wishield.db")
cursor = connection.cursor()

# Remove only the test records we created
cursor.execute("DELETE FROM alerts")
cursor.execute("DELETE FROM activity_logs")
cursor.execute("DELETE FROM devices")

connection.commit()

print("Test data removed successfully!")

connection.close()