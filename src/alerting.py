import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def generate_alert(subject, body):
    # Email configuration
    sender_email = os.getenv("SENDER_EMAIL")
    receiver_email = os.getenv("RECEIVER_EMAIL")

    # Email content
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    message.attach(MIMEText(body, "plain"))

    # Send email
    try:
        smtp_host = os.getenv("SMTP_HOST")
        smtp_port = os.getenv("SMTP_PORT")

        server = smtplib.SMTP(smtp_host, smtp_port)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        print("Alert email sent successfully.")
    except Exception as e:
        print("Error sending email:", e)


if __name__ == "__main__":
    generate_alert("Testing Email", "Hi, this is a test email for HIDS development. Please ignore.")

