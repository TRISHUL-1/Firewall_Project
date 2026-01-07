from email.mime.text import MIMEText
import base64
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle

# Scope for sending email
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CREDENTIAL_FILE = os.path.join(BASE_DIR, 'credentials', 'credentials.json')
TOKEN_FILE = os.path.join(BASE_DIR, 'credentials', 'token.json')

def gmail_authenticate():
    creds = None

    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)


    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIAL_FILE, SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)

def send_email(service, to, subject, message_text):

    #sending the email
    message = MIMEText(message_text)
    message['to'] = to
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    body = {'raw': raw_message}

    #acknowledgement
    result = service.users().messages().send(userId="me", body=body).execute()
    print("Email sent! Message ID:", result['id'])

def get_information():
    info_dict = dict()
    
    #collecting information from the user
    info_dict['to'] = input("Enter the reciever email: ")
    info_dict['subject'] = "NETWORK SECURITY ALERT !!"
    info_dict['message_text'] = "Firewall has detected an anomaly please check the logs for more info"

    return info_dict
