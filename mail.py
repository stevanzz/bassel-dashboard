import smtplib, ssl


class Mail:
    port = 587  # For starttls
    smtp_server = "smtp.gmail.com"
    sender_email = "sender@gmail.com"
    password = input("Type your password and press enter:")
    context = ssl.create_default_context()

    def send_email(self, receiver_email, message):
        with smtplib.SMTP(self.smtp_server, self.port) as server:
            server.ehlo()  # Can be omitted
            server.starttls(context=self.context)
            server.ehlo()  # Can be omitted
            server.login(self.sender_email, self.password)
            server.sendmail(self.sender_email, receiver_email, message)