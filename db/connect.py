import pandas as pd
from sqlalchemy import create_engine
import os
from dotenv import load_dotenv
load_dotenv()

HOST = os.getenv("DB_HOST")
PORT = os.getenv("DB_PORT")
DB = os.getenv("DB_NAME")
USER = os.getenv("DB_USER")
TABLE = os.getenv("DB_TABLE")


def load_threat_data():
    conn_str = f"postgresql://{USER}@{HOST}:{PORT}/{DB}"
    engine = create_engine(conn_str)

    query = f"SELECT * FROM {TABLE};"

    df = pd.read_sql(query, engine)
    return df
