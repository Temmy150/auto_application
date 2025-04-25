import os
import re
import base64
import requests

from flask import Flask, session, redirect, url_for, request, render_template_string
from bs4 import BeautifulSoup

# Google OAuth libraries
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = "Temmy"  # Replace with something secure

# The JSON file you downloaded from Google Cloud (rename if necessary)
CLIENT_SECRETS_FILE = "client_secret.json"

# Which API scopes you need. For sending email, we use gmail.send.
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

# Inline HTML templates (for demo purposes). In a real app, use separate template files.
INDEX_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>JobApp: Send via OAuth</title>
</head>
<body>
  <h1>Welcome to the Job Application Sender</h1>
  {% if 'credentials' not in session %}
    <p>You are not logged in. <a href="{{ url_for('login') }}">Sign in with Google</a></p>
  {% else %}
    <p>You are logged in. <a href="{{ url_for('logout') }}">Logout</a></p>
    <p><a href="{{ url_for('show_form') }}">Go to Application Form</a></p>
  {% endif %}
</body>
</html>"""

FORM_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>Send My Apps</title>
</head>
<body>
  <h2>Send a Job Application</h2>
  <form action="{{ url_for('apply') }}" method="POST">
    <label for="job_url">Job Posting URL:</label>
    <input type="text" id="job_url" name="job_url" size="60" required>
    <br><br>
    <label for="position">Position Title (optional):</label>
    <input type="text" id="position" name="position" size="40">
    <br><br>
    <input type="submit" value="Send Application">
  </form>
  <br>
  <a href="{{ url_for('index') }}">Back to Home</a>
</body>
</html>"""

@app.route("/")
def index():
    """
    Landing page. If logged in, shows a link to the form;
    otherwise, offers a 'Sign in with Google' button.
    """
    return render_template_string(INDEX_HTML)

@app.route("/login")
def login():
    """
    Initiates the OAuth flow by creating a Flow object
    and redirecting the user to Google's consent screen.
    """
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true"
    )
    session["state"] = state
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    """
    Google redirects the user back here with an authorization code.
    This exchanges the code for an access/refresh token pair and stores them.
    """
    state = session.get("state")
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session["credentials"] = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes
    }
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    """Removes OAuth credentials from session."""
    session.pop("credentials", None)
    return redirect(url_for("index"))

@app.route("/form")
def show_form():
    """
    Displays a simple form for the user to input a job URL and position title.
    """
    if "credentials" not in session:
        return redirect(url_for("index"))
    return render_template_string(FORM_HTML)

@app.route("/apply", methods=["POST"])
def apply():
    """
    Scrapes the provided job URL for an email address,
    then sends an application email to that address using the user's Gmail.
    """
    if "credentials" not in session:
        return "You are not logged in with Google.", 403

    job_url = request.form.get("job_url", "").strip()
    position = request.form.get("position", "A position").strip()

    if not job_url:
        return "Error: job URL is required."

    # Scrape the URL for an email address
    email_found = scrape_for_email(job_url)
    if not email_found:
        return f"No email found on {job_url}. Could not send."

    # Send the email via the user's Gmail (using OAuth token)
    success, message = send_via_gmail_api(
        creds_data=session["credentials"],
        recipient=email_found,
        subject=f"Application for {position}",
        body=f"""Dear Hiring Manager,

I am interested in the {position} role.
Please let me know if you need any additional info.

Best regards,
An OAuth User
"""
    )

    if success:
        return f"Application sent to {email_found}!"
    else:
        return f"Failed to send. Error: {message}", 500

def scrape_for_email(url):
    """
    Fetches the URL, extracts its text, and searches for an email pattern.
    Returns the first email match or None.
    """
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        text = soup.get_text(separator=" ", strip=True)
        pattern = r"([a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+)"
        match = re.search(pattern, text)
        return match.group(1) if match else None
    except Exception as e:
        print("Scrape error:", e)
        return None

def send_via_gmail_api(creds_data, recipient, subject, body):
    """
    Uses the Gmail API with the user's OAuth token to send an email.
    Returns (True, "message") on success, or (False, "error message") on failure.
    """
    try:
        creds = Credentials(**creds_data)
        service = build("gmail", "v1", credentials=creds)
        from email.mime.text import MIMEText
        mime_msg = MIMEText(body)
        mime_msg["to"] = recipient
        mime_msg["subject"] = subject
        raw = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode("utf-8")
        message_body = {"raw": raw}
        result = service.users().messages().send(userId="me", body=message_body).execute()
        return (True, f"Message sent with ID: {result.get('id')}")
    except Exception as e:
        return (False, str(e))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
