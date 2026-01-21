#!/usr/bin/env python3
import mysql.connector

# Database credentials
config = {
    'host': '207.180.193.215',
    'port': 3306,
    'user': 'mailarmor_db',
    'password': '9mpB13qWO8)0',
    'database': '00002_hackntraincom_IN_MS'
}

try:
    # Connect to database
    conn = mysql.connector.connect(**config)
    cursor = conn.cursor()

    print('DATABASE QUERY: scan_signals')
    print('=' * 60)

    # Count unique records where email_id starts with 'test-Sp1-'
    query_count = """
        SELECT COUNT(DISTINCT email_id)
        FROM scan_signals
        WHERE email_id LIKE 'test-Sp1-%'
    """
    cursor.execute(query_count)
    count = cursor.fetchone()[0]
    print(f'Unique records with email_id starting with "test-Sp1-": {count}')

    # Get sample of email_ids
    query_samples = """
        SELECT DISTINCT email_id
        FROM scan_signals
        WHERE email_id LIKE 'test-Sp1-%'
        ORDER BY email_id
        LIMIT 20
    """
    cursor.execute(query_samples)
    samples = cursor.fetchall()

    print(f'\nSample email_ids (first 20):')
    for row in samples:
        print(f'  {row[0]}')

    cursor.close()
    conn.close()

except mysql.connector.Error as err:
    print(f'Database Error: {err}')
except Exception as e:
    print(f'Error: {e}')