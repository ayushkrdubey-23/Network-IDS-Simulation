
import sqlite3
from pathlib import Path

database_path = (
    Path(__file__).resolve().parent
    / "data"
    / "ids_database.db"
)

connection = sqlite3.connect(database_path)

tables = connection.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
    ORDER BY name
""").fetchall()

print("\nDATABASE TABLES")

for table in tables:
    print(table[0])

count = connection.execute(
    "SELECT COUNT(*) FROM alerts"
).fetchone()[0]

print(f"\nTotal imported alerts: {count}")

risk_distribution = connection.execute("""
    SELECT risk_level, COUNT(*)
    FROM alerts
    GROUP BY risk_level
""").fetchall()

print("\nRISK DISTRIBUTION")

for risk, total in risk_distribution:
    print(f"{risk}: {total}")

connection.close()
