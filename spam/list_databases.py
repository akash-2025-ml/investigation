#!/usr/bin/env python3
import mysql.connector

# Database credentials
config = {
    'host': '207.180.193.215',
    'port': 3306,
    'user': 'mailarmor_db',
    'password': '9mpB13qWO8)0'
}

try:
    # Connect to database
    conn = mysql.connector.connect(**config)
    cursor = conn.cursor()

    print('LISTING AVAILABLE DATABASES')
    print('=' * 60)

    cursor.execute("SHOW DATABASES")
    databases = cursor.fetchall()

    for db in databases:
        print(f'  {db[0]}')

    cursor.close()
    conn.close()

except mysql.connector.Error as err:
    print(f'Database Error: {err}')
except Exception as e:
    print(f'Error: {e}')