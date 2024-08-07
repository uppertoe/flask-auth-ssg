from flask import Flask, redirect, url_for, session, request, abort, send_from_directory
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'insecure-secret-key')
app.debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

# Configuration variables
AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID')
AZURE_AUTHORITY_URL = f'https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0'
AZURE_AUTHORIZE_URL = f'{AZURE_AUTHORITY_URL}/authorize'
AZURE_TOKEN_URL = f'{AZURE_AUTHORITY_URL}/token'
AZURE_SCOPE = 'User.read'

if not all([AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID]):
    raise ValueError("Missing one or more environment variables for Azure AD configuration.")

PUBLIC_DIRECTORY = 'public'

os.makedirs(PUBLIC_DIRECTORY, exist_ok=True)

oauth = OAuth(app)
azure = oauth.register(
    name='azure',
    client_id=AZURE_CLIENT_ID,
    client_secret=AZURE_CLIENT_SECRET,
    authorize_url=AZURE_AUTHORIZE_URL,
    authorize_params=None,
    access_token_url=AZURE_TOKEN_URL,
    access_token_params=None,
    client_kwargs={'scope': AZURE_SCOPE},
)

@app.before_request
def check_https():
    if not app.debug and not request.is_secure:
        return redirect(request.url.replace("http://", "https://"))

@app.route('/')
def index():
    if app.debug or is_authenticated():
        return send_from_directory(PUBLIC_DIRECTORY, 'index.html')
    return redirect(url_for('login'))

@app.route('/login')
def login():
    redirect_uri = url_for('authorized', _external=True)
    return azure.authorize_redirect(redirect_uri)

@app.route('/logout')
def logout():
    session.pop('azure_token', None)
    session.pop('expires_at', None)
    return redirect(url_for('index'))

@app.route('/login/authorized')
def authorized():
    token = azure.authorize_access_token()
    if token is None:
        return 'Access denied: reason={} error={}'.format(
            request.args.get('error'), request.args.get('error_description')
        )
    session['azure_token'] = token
    session['expires_at'] = datetime.now(tz=timezone.utc) + timedelta(seconds=token['expires_in'])
    return redirect(url_for('index'))

def is_authenticated():
    token = session.get('azure_token')
    expires_at = session.get('expires_at')
    if token and expires_at:
        if datetime.now(tz=timezone.utc) < expires_at:
            return True
    return False

@app.route('/<path:filename>')
def serve_static(filename):
    if not app.debug and not is_authenticated():
        return redirect(url_for('login'))
    
    full_path = os.path.join(PUBLIC_DIRECTORY, filename)
    
    if os.path.isdir(full_path):
        index_path = os.path.join(full_path, 'index.html')
        if os.path.isfile(index_path):
            return send_from_directory(full_path, 'index.html')
        else:
            abort(404)
    else:
        if os.path.isfile(full_path):
            return send_from_directory(PUBLIC_DIRECTORY, filename)
        else:
            abort(404)

if __name__ == '__main__':
    app.run(port=5005)  # Use a proper SSL certificate in production
