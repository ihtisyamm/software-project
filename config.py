from dotenv import load_dotenv
import os

WTF_CSRF_ENABLE = True
SECRET_KEY = os.getenv('SECRET_KEY')