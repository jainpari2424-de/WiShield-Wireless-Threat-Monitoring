import sqlite3

connection = sqlite3.connect("database/wishield.db")
cursor = connection.cursor()

cursor.execute("SELECT * FROM activity_logs")

logs = cursor.fetchall()

for log in logs:
    print(log)

connection.close()