import mysql.connector

try:
    conn = mysql.connector.connect(
        host="localhost",
        user="shieldpatch_user",
        password="yourpassword",
        database="shieldpatch_db"
    )
    cursor = conn.cursor()
    cursor.execute("SHOW TABLES;")
    tables = cursor.fetchall()
    print("Connected! Tables:", tables)
    conn.close()
except Exception as e:
    print("Error:", e)
