from flask_mail import Message
from app import app, mail
from threading import Thread
from .decorators import async


@async
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(subject, recipients, html_body): #text_body
    msg = Message(subject, recipients=recipients)
    # msg.body = text_body
    msg.html = html_body
    send_async_email(app, msg)