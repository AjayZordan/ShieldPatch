# db.py
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "shieldpatch")

# using mysql+mysqlconnector
DATABASE_URL = "mysql+pymysql://shieldpatch_user:ajaykumar%40040702@localhost:3306/ShieldPatch"

# engine with pool_pre_ping to avoid stale connections
engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def get_session():
    return SessionLocal()