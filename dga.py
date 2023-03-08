# import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib

# tlds = ['.com', '.net', '.org', '.io', '.info', '.biz']

# first = 'aeiou'
# second = 'bcdfghjklmnpqrstvwxyz'

# def generate_domain():
    
#     length = random.randint(5,10)
#     name = ''
#     for i in range(length):
#         if i%2== 0:
#             name += random.choice(second)
#         else:
#             name += random.choice(first)

#     tld = random.choice(tlds)

#     return name + tld


# for i in range(20):
#     file = open("domaingenerator.txt",'a')
#     file.write(generate_domain()+'\n')






#fucntion for sending mail.
def send_alert(mal_domain):
    """Function for sending the mail to admin account
    with their respective ip address. And the files contains the log of the user.
    """

    #asssining the header part.
    msg = MIMEMultipart()
    msg['from'] = 'hackertarun12@gmail.com'
    msg['To'] = "linux.tarun1@gmail.com"
    msg['Subject'] = "High Alert"
    msg.attach(MIMEText(f"We found a traffic to suspicoud Domain"))
    #end of the header part of the mail.

    body = "This is alerted because one of your customer visited a very malicious domain."
    body+= 'Please check for your end and confirm this whether this traffic is expected or not.\n'
    body += 'Alert Type: Suspicious Domain.\n'
    body += f'Domain Name: {mal_domain}\n'
    body += "We found this domain from Domain Generator Algorithm. Review this site and add it your whitelist if you think it is safe or\n"
    body += "If you find this as suspicous we'll keep an eye on the working of the site. Thank you."

    msg.attach(MIMEText(body, 'plain'))
    #starting the smpt server to send the attachments.
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login("hackertarun12@gmail.com","qbtaflvxnbsxyusa")
    server.sendmail("hackertarun12@gmail.com", "linux.tarun1@gmail.com", msg.as_string())
    server.quit()
    #quitting the server.

#ip address of the local device.

#calling the function to send mail.


def dectect_mal_domain():
    file = open("dnsvalues.txt", 'r')
    file2 = open("domaingenerator.txt",'r')
    for x in file.read().splitlines():
        if x in file2.read().splitlines():
            send_alert(x)
            print("Alerted.")
        else:
            print("not found")

dectect_mal_domain()

