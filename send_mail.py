from email.mime.text import MIMEText
import base64
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Scope for sending email
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def gmail_authenticate():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def send_email(service, to, subject, message_text):
    message = MIMEText(message_text)
    message['to'] = to
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    body = {'raw': raw_message}
    return service.users().messages().send(userId="me", body=body).execute()

def get_information():
    info_dict = dict()
    
    info_dict['to'] = input("Enter the reciever email: ")
    info_dict['subject'] = "NETWORK SECURITY ALERT !!"
    info_dict['message_text'] = "Firewall has detected an anomaly please check the logs for more info"

    return info_dict


# if __name__ == "__main__":
#     gmail_service = gmail_authenticate()
#     result = send_email(gmail_service, "example@mail.com", "Hello from Python!", "This is a test message.")
#     print("Email sent! Message ID:", result['id'])
