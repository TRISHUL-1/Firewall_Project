from dotenv import load_dotenv
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

load_dotenv()

database_url = os.getenv("DATABASE_URL")

engine = create_engine(database_url)

sessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)