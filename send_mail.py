#importing the libraries.
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib
#End of the libraries.

#function for finding the ip of the device.
def ip_of_the_device():
    """finds the ip address of the user using socket library
        useful for sending the report to the Analysts."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8',80))
    #gets the ip address of the device.
    ip = s.getsockname()[0]
    s.close()
    return ip

#fucntion for sending mail.
def send_mail(ip_address):
    """Function for sending the mail to admin account
    with their respective ip address. And the files contains the log of the user.
    """

    #asssining the header part.
    msg = MIMEMultipart()
    msg['from'] = 'hackertarun12@gmail.com'
    msg['To'] = "linux.tarun1@gmail.com"
    msg['Subject'] = "Log Report"
    msg.attach(MIMEText(f"Here is the log of the IP {ip_address} address."))
    #end of the header part of the mail.

    #using for loop for sending the all the log files.
    for filename in ['dnsvalues.txt','ipvalues.txt', 'mailiciousfiles.txt', 'whitelist.txt','maliciousdns.txt']:
        with open(filename,"rb") as f:
            attachment = MIMEBase("application","octet-stream")
            attachment.set_payload((f).read())
        encoders.encode_base64(attachment)
        attachment.add_header("Content-Disposition",f"attachemnt;filename={filename}")
        msg.attach(attachment)
    #end of the body part of the email.

    #starting the smpt server to send the attachments.
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login("hackertarun12@gmail.com","qbtaflvxnbsxyusa")
    server.sendmail("hackertarun12@gmail.com", "linux.tarun1@gmail.com", msg.as_string())
    server.quit()
    #quitting the server.

#ip address of the local device.
ip = ip_of_the_device()
#calling the function to send mail.
send_mail(ip)