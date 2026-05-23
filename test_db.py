from sqlalchemy import create_engine, text
from dotenv import load_dotenv
from urllib.parse import quote_plus
import os

# Load .env variables
load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")

# Safely encode password
DB_PASSWORD = quote_plus(
    os.getenv("DB_PASSWORD")
)

DATABASE_URL = (
    f"postgresql+psycopg2://"
    f"{DB_USER}:{DB_PASSWORD}@"
    f"{DB_HOST}:{DB_PORT}/"
    f"{DB_NAME}"
)

print("\nDATABASE URL:")
print(DATABASE_URL)

try:

    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True
    )

    with engine.connect() as conn:

        result = conn.execute(
            text("SELECT version();")
        )

        print("\n✅ DATABASE CONNECTED!\n")

        for row in result:
            print(row[0])

except Exception as e:

    print("\n❌ DATABASE CONNECTION FAILED\n")

    print(e)