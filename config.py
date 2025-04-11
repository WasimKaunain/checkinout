import os
from dotenv import load_dotenv
from urllib.parse import quote_plus  # Add this import

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    
    DB_USERNAME = os.getenv('DB_USERNAME')
    DB_PASSWORD = quote_plus(os.getenv('DB_PASSWORD'))  # URL-encode the password
    DB_NAME = os.getenv('DB_NAME')
    
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@localhost/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

