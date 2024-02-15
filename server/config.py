from dotenv import load_dotenv
import os

load_dotenv()

# Flask app configuration
DEBUG = True 
SECRET_KEY = '1#qw#>wI(`uu<?liPG8D!aw>;(SMn.'  

# PostgreSQL database configuration
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
SQLALCHEMY_TRACK_MODIFICATIONS = False

# File Upload Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}  

# CORS Configuration (if needed, for handling cross-origin requests)
# CORS_ENABLED = False
# CORS_ORIGINS = ["http://example.com", "https://example.com"]
# CORS_SUPPORTS_CREDENTIALS = True

# Flask-Mail Configuration (for sending emails, if needed)
# MAIL_SERVER = 'smtp.gmail.com'
# MAIL_PORT = 587
# MAIL_USE_TLS = True
# MAIL_USE_SSL = False
# MAIL_USERNAME = 'your_email@example.com'
# MAIL_PASSWORD = 'your_email_password'
# MAIL_DEFAULT_SENDER = 'your_email@example.com'

# Configuration for securely hashing and salting passwords
BCRYPT_LOG_ROUNDS = 12 

# JWT (JSON Web Tokens) configuration for authentication 
JWT_SECRET_KEY = 'nqf`i+k{cTTo|<M#(&w@j_S1x@K"OG'  
JWT_BLACKLIST_ENABLED = True
JWT_BLACKLIST_TOKEN_CHECKS = ['access']
JWT_ACCESS_TOKEN_EXPIRES = 3600  
JWT_REFRESH_TOKEN_EXPIRES = 604800  
