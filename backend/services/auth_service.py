# services/auth_service.py
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# OAuth configuration
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/gmail.readonly"
]

def get_oauth_flow():
    """Create and return OAuth flow"""
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("REDIRECT_URI")
    
    if not client_id or not client_secret:
        raise ValueError("Missing OAuth credentials. Check environment variables.")
    
    # For local development only
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    
    # Check if credentials file exists, otherwise create from env vars
    if os.path.exists("credentials.json"):
        flow = Flow.from_client_secrets_file(
            "credentials.json",
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
    else:
        # Create flow from client config
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [redirect_uri]
                }
            },
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
    
    return flow

def creds_to_dict(creds: Credentials):
    """Convert Credentials object to dictionary"""
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

def validate_token(token):
    """Validate an OAuth token"""
    try:
        creds = Credentials(token=token)
        return not creds.expired
    except Exception:
        return False