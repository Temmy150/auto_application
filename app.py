import os
import io
import re
import base64
import requests

from flask import Flask, session, redirect, url_for, request, render_template_string
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Google OAuth libraries
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# Supabase client
from supabase import create_client
from werkzeug.datastructures import FileStorage

# Load environment variables
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")

# Initialize Supabase
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
UPLOAD_BUCKET = "defaults"

# Initialize Flask app
app = Flask(__name__)
app.secret_key = SECRET_KEY

# OAuth configuration
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = [
    "https://www.googleapis.com/auth/gmail.send"
]

# Templates
INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>JobApp</title>
</head>
<body>
    <h1>Job Application Sender</h1>
    {% if 'credentials' not in session %}
        <p><a href="{{ url_for('login') }}">Sign in with Google</a></p>
    {% else %}
        <p><a href="{{ url_for('logout') }}">Logout</a></p>
        <p><a href="{{ url_for('show_form') }}">Send Application</a></p>
        <p><a href="{{ url_for('manage_defaults') }}">Manage Default Documents</a></p>
    {% endif %}
</body>
</html>
"""

FORM_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Send Application</title>
</head>
<body>
    <h2>Send a Job Application</h2>
    <form action="{{ url_for('apply') }}" method="POST" enctype="multipart/form-data">
        <label>Job Posting URL:</label>
        <input type="text" name="job_url" value="{{ job_url }}" readonly required>
        <br><br>
        <label>Position Title:</label>
        <input type="text" name="position">
        <br><br>
        <label>Extra Attachments:</label>
        <input type="file" name="attachments" multiple>
        <br><br>
        <input type="submit" value="Send">
    </form>
    <a href="{{ url_for('index') }}">Home</a>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true"
    )
    session['state'] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session.get('state'),
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    return redirect(url_for('index'))

@app.route("/logout")
def logout():
    session.pop('credentials', None)
    return redirect(url_for('index'))

@app.route("/manage-defaults", methods=["GET", "POST"])
def manage_defaults():
    if 'credentials' not in session:
        return redirect(url_for('index'))
    creds = Credentials(**session['credentials'])
    user_info = build('oauth2', 'v2', credentials=creds).userinfo().get().execute()
    email = user_info['email']
    if request.method == 'POST':
        for f in request.files.getlist('default_files'):
            if not f.filename:
                continue
            path = f"{email}/{f.filename}"
            supabase.storage.from_(UPLOAD_BUCKET).upload(
                path,
                io.BytesIO(f.read()),
                {'content-type': f.mimetype}
            )
            supabase.table('user_defaults').insert({
                'user_email': email,
                'path': path
            }).execute()
        return redirect(url_for('manage_defaults'))
    resp = supabase.table('user_defaults').select('path').eq('user_email', email).execute()
    existing = [r['path'].split('/', 1)[1] for r in resp.data]
    return render_template_string(
        """
        <h1>Manage Default Documents</h1>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="default_files" multiple><br><br>
            <button type="submit">Upload Defaults</button>
        </form>
        <h2>Saved:</h2>
        <ul>{% for fn in existing %}<li>{{ fn }}</li>{% endfor %}</ul>
        <a href="{{ url_for('index') }}">Home</a>
        """,
        existing=existing
    )

@app.route("/form")
def show_form():
    if 'credentials' not in session:
        return redirect(url_for('index'))
    job_url = request.args.get('job_url', '')
    return render_template_string(FORM_HTML, job_url=job_url)

@app.route("/apply", methods=["POST"])
def apply():
    if 'credentials' not in session:
        return "Not logged in", 403
    job_url = request.form['job_url']
    position = request.form.get('position', 'Position').strip()
    resp = requests.get(job_url, timeout=10)
    soup = BeautifulSoup(resp.text, 'html.parser')
    text = soup.get_text(' ', strip=True)
    match = re.search(r'([A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+)', text)
    if not match:
        return 'No email found', 400
    recipient = match.group(1)
    creds = Credentials(**session['credentials'])
    user_info = build('oauth2', 'v2', credentials=creds).userinfo().get().execute()
    email = user_info['email']
    db_resp = supabase.table('user_defaults').select('path').eq('user_email', email).execute()
    default_paths = [r['path'] for r in db_resp.data]
    default_files = []
    for path in default_paths:
        data = supabase.storage.from_(UPLOAD_BUCKET).download(path)
        if data:
            stream = io.BytesIO(data)
            default_files.append(FileStorage(stream=stream, filename=path.split('/', 1)[1]))
    extras = request.files.getlist('attachments')
    attachments = default_files + extras
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders
    msg = MIMEMultipart()
    msg['To'] = recipient
    msg['Subject'] = f'Application for {position}'
    msg.attach(MIMEText(f'Dear Hiring Manager,\n\nI am interested in the {position} role.\n', 'plain'))
    for fs in attachments:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(fs.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{fs.filename}"')
        msg.attach(part)
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    gmail = build('gmail', 'v1', credentials=Credentials(**session['credentials']))
    gmail.users().messages().send(userId='me', body={'raw': raw}).execute()
    return f"Sent to {recipient}!"

@app.route("/privacy")
def privacy():
    return render_template_string('<h1>Privacy Policy</h1><p>We only use your data to send applications you authorize.</p>')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
