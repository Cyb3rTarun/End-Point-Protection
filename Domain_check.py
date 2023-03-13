import whois
from datetime import datetime
import ssl
import socket
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
# from email.mime.base import MIMEBase
# from email import encoders
import smtplib

def rem_duplication():
    dnsvalues_file = open('dnsvalues.txt','r')
    domains = set()

    for value in dnsvalues_file.read().splitlines():

        domains.add(value)

    rem_dup = open("removed_duplicates_dns.txt",'a')
    for x in domains:
        rem_dup.write(x+'\n')


def website_age(x):
    whois_info = whois.whois(x)

    if type(whois_info.creation_date) is list:
        creation_date = whois_info.creation_date[0]
    else:
        creation_date = whois_info.creation_date

    if creation_date is not None:
        age = (datetime.now() - creation_date).days //365
        print(f'The domain is {x} - {age} years old. \u2713')
        if age<1:
            return True
    else:
        print('unable to determine domain age. \u2717')

# website_age()

def ssl_check(x):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((x, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=x) as ssock:
                cert = ssock.getpeercert()
            
        print("SSL Check Found \u2713")
    except:
        print("SSL Not Found \u2717")
# ssl_check()

def dga_check():
    file = open("removed_duplicates_dns.txt", 'r')
    file2 = open("domaingenerator.txt",'r')
    for x in file.read().splitlines():
        if x in file2.read().splitlines():
            print("Alerted.")
        else:
            print("not found")

# dga_check()
def virus_check(x):
    """This functions checks for the domains requested by the user.
        And then checks with virustotal by making a api call. And tells whether
        the website is malicious or not."""

    url = "https://www.virustotal.com/api/v3/domains/"+x
    headers = {
        "accept": "application/json",
        "x-apikey": "68451e7265819cf12ba5c162d3782262a613195843303775dd2139858c216643"
    }
    #response from virsutotal.
    response = requests.get(url, headers=headers)
    #getting json data from the website
    data = response.json()
    #if there is any error prints error message can be server error or user end error.
    try:
        print(x+"-",data['data']['attributes']['last_analysis_stats']['malicious'])
        if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            file = open("maliciousdns.txt",'a')
            file.write(x)
    #if the domain is not scanned by the virustotal engines.
    except:
        print("{} - Domain Not Found. Try to Avoid this url.".format(x))
#calling the function.

# virus_check()

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

file = open('rd_dnsvalues.txt','r')
file1 = open('whitelist.txt','r')
whitelist_list = []
for y in file1.read().splitlines():
    whitelist_list.append(y)

print(whitelist_list)
for x in file.read().splitlines():
    check1 = website_age(x)
    check2 = ssl_check(x)
    check3 = virus_check(x)

    if (check1 or check2 or check3) and (x not in whitelist_list) == True:
        print("Sending Mail.")
        # send_alert(x)
