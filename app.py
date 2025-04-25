import os
import re
import io
import base64
import requests

from flask import Flask, session, redirect, url_for, request, render_template_string
from bs4 import BeautifulSoup

from dotenv import load_dotenv
from supabase import create_client

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from werkzeug.datastructures import FileStorage

# ── Load environment ───────────────────────────────────────────────────────────
load_dotenv()  # reads .env into os.environ

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase     = create_client(SUPABASE_URL, SUPABASE_KEY)

CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# ── HTML TEMPLATES ─────────────────────────────────────────────────────────────
INDEX_HTML = """
<!DOCTYPE html>
<html>
<head><title>JobApp</title></head>
<body>
  <h1>Welcome to JobApp</h1>
  {% if 'credentials' not in session %}
    <p><a href="{{ url_for('login') }}">Sign in with Google</a></p>
  {% else %}
    <p><a href="{{ url_for('logout') }}">Logout</a></p>
    <p><a href="{{ url_for('show_form') }}">Send Application</a></p>
    <p><a href="{{ url_for('manage_defaults') }}">Manage Default Docs</a></p>
  {% endif %}
</body>
</html>
"""

FORM_HTML = """
<!DOCTYPE html>
<html>
<head><title>Send Application</title></head>
<body>
  <h2>Send Job Application</h2>
  <form action="{{ url_for('apply') }}" method="POST" enctype="multipart/form-data">
    <label>Job URL:</label>
    <input type="text" name="job_url" size="60" required><br><br>
    <label>Position:</label>
    <input type="text" name="position" size="40"><br><br>
    <label>Extra Attachments:</label>
    <input type="file" name="attachments" multiple><br><br>
    <button type="submit">Send</button>
  </form>
  <p><a href="{{ url_for('index') }}">Home</a></p>
</body>
</html>
"""

MANAGE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Manage Defaults</title></head>
<body>
  <h2>Manage Default Documents</h2>
  <form method="POST" enctype="multipart/form-data">
    <input type="file" name="default_files" multiple><br><br>
    <button type="submit">Upload Defaults</button>
  </form>
  <h3>Current Defaults:</h3>
  <ul>
    {% for fn in existing %}
      <li>{{ fn }}</li>
    {% endfor %}
  </ul>
  <p><a href="{{ url_for('index') }}">Home</a></p>
</body>
</html>
"""

# ── ROUTES ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true"
    )
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session["credentials"] = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes
    }
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.pop("credentials", None)
    return redirect(url_for("index"))

@app.route("/form")
def show_form():
    if "credentials" not in session:
        return redirect(url_for("index"))
    return render_template_string(FORM_HTML)

@app.route("/apply", methods=["POST"])
def apply():
    if "credentials" not in session:
        return "Not logged in", 403

    job_url = request.form["job_url"].strip()
    position = request.form.get("position", "Position").strip()

    email = scrape_for_email(job_url)
    if not email:
        return f"No email found at {job_url}", 400

    # Fetch default docs
    creds = Credentials(**session["credentials"])
    user_info = build("oauth2", "v2", credentials=creds).userinfo().get().execute()
    user_email = user_info["email"]

    resp = supabase.table("user_defaults")\
                   .select("path")\
                   .eq("user_email", user_email)\
                   .execute()
    default_paths = [row["path"] for row in resp.data]

    default_files = []
    for path in default_paths:
        data = supabase.storage.from_("defaults").download(path)
        if data:
            stream = io.BytesIO(data)
            default_files.append(FileStorage(stream=stream, filename=path.split("/",1)[1]))

    extras = request.files.getlist("attachments")
    attachments = default_files + extras

    success, msg = send_via_gmail_api(
        session["credentials"], email,
        f"Application for {position}",
        f"Dear Hiring Manager,\n\nI am interested in {position}.\n\nBest,\nOAuth User",
        attachments
    )
    return (f"Sent to {email}", 200) if success else (f"Error: {msg}", 500)

@app.route("/manage-defaults", methods=["GET", "POST"])
def manage_defaults():
    if "credentials" not in session:
        return redirect(url_for("index"))

    creds = Credentials(**session["credentials"])
    user_info = build("oauth2", "v2", credentials=creds).userinfo().get().execute()
    user_email = user_info["email"]

    if request.method == "POST":
        for f in request.files.getlist("default_files"):
            if not f.filename:
                continue
            path = f"{user_email}/{f.filename}"
            supabase.storage.from_("defaults")\
                   .upload(path, io.BytesIO(f.read()), {"content-type": f.mimetype})
            supabase.table("user_defaults")\
                   .insert({"user_email": user_email, "path": path})\
                   .execute()
        return redirect(url_for("manage_defaults"))

    resp = supabase.table("user_defaults")\
                   .select("path")\
                   .eq("user_email", user_email)\
                   .execute()
    existing = [row["path"].split("/",1)[1] for row in resp.data]
    return render_template_string(MANAGE_HTML, existing=existing)

# ── HELPERS ───────────────────────────────────────────────────────────────────
def scrape_for_email(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        text = BeautifulSoup(r.text, "html.parser").get_text(" ", strip=True)
        m = re.search(r"([A-Za-z0-9_.+\-]+@[A-Za-z0-9\-]+\.[A-Za-z0-9\-.]+)", text)
        return m.group(1) if m else None
    except Exception:
        return None

def send_via_gmail_api(creds_data, recipient, subject, body, attachments=None):
    try:
        creds = Credentials(**creds_data)
        service = build("gmail", "v1", credentials=creds)

        msg = MIMEMultipart()
        msg["to"] = recipient
        msg["subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        for f in attachments or []:
            part = MIMEBase("application", "octet-stream")
            data = f.read()
            part.set_payload(data)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="{f.filename}"')
            msg.attach(part)

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        service.users().messages().send(userId="me", body={"raw": raw}).execute()
        return True, "OK"
    except Exception as e:
        return False, str(e)

# ── RUN ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
