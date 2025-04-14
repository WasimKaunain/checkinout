import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')

    DB_USERNAME = os.getenv('DB_USERNAME')
    DB_PASSWORD = quote_plus(os.getenv('DB_PASSWORD'))  # URL-encode the password

    # Primary DB (your app DB)
    DB_NAME = os.getenv('DB_NAME')
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@10.0.116.125/{DB_NAME}"

    # JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')  # Keep this safe
    # JWT_ALGORITHM = 'HS256'
    # JWT_EXP_DELTA_SECONDS = 300  # 5 minutes

    # Bind for evaluation DB (cs432cims)
    EVAL_DB_NAME = os.getenv('EVAL_DB_NAME')
    SQLALCHEMY_BINDS = {
        'cims': f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@10.0.116.125/{EVAL_DB_NAME}"
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False
