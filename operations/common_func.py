import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests, os

class CommonOpertion():

    def __init__(self):
        pass

    def get_public_ip(self):
        ip = requests.get('https://api.ipify.org').text
        return ip

    def send_mail(self, to_email, subject, html_body):
        # Email configuration
        SMTP_SERVER = 'smtp.gmail.com'  # Use your SMTP server address
        SMTP_PORT = 587  # For TLS
        USERNAME = 'codescatter8980@gmail.com'
        PASSWORD = 'wqadvalvlkyjokzn'

        # Create message
        msg = MIMEMultipart()
        msg['From'] = USERNAME
        msg['To'] = to_email
        msg['Subject'] = subject

        # Message content
        body = 'This is a test email sent from Python!'
        msg.attach(MIMEText(html_body, 'html'))

        # Sending email
        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()  # Secure the connection
            server.login(USERNAME, PASSWORD)
            text = msg.as_string()
            server.sendmail(USERNAME, to_email, text)
            print("Email sent successfully")
        except Exception as e:
            print(f"Failed to send email: {str(e)}")
        finally:
            server.quit()

    def create_folder_path(self, folder_path):
        try:
            os.makedirs(folder_path, exist_ok=True)
        except OSError as e:
            print(f"Error: {e}")
        return folder_path

    def get_folders(self, path):
        return [name for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))]

    def get_files(self, path):
        return [name for name in os.listdir(path) if os.path.isfile(os.path.join(path, name))]

    def get_previous_numbers(self, num, count=4):
        return [num - i for i in range(1, count + 1)]

    def get_previous_numbers_list(self, num):
        return list(range(num - 1, 0, -1))

