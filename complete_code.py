import requests,hashlib
from scapy.layers.inet import IP
from scapy.layers.dns import DNS,DNSQR
from scapy.sendrecv import sniff
from collections import Counter
import os
import sched, time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import socket


def DDos_Attack(src_packets):

    file = open(src_packets,'r')
    ip = file.read()
    ip_values_count = Counter(ip.split())

    ip_whitelist = []
    file = open('whitelist.txt','r')
    content_list = file.readlines()
    for x in content_list:
        ip_whitelist.append(x.rstrip('\n'))

    for ip_number,ip_count in ip_values_count.items():
        if ip_count>1000 and ip_number not in ip_whitelist:

            print("{} A Ddos attack is detected from this Address. The Activity is been logged.".format(ip_number))


def src_and_dst(data):

    ip_value_list = []
    dns_query(data)
    for packet in data:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print("[*] Source --> \033[32m{:15}\033[0m destination --> \033[32m{}\033[0m ".format(src_ip,dst_ip))
            ip_value_list.append(src_ip)        
            
    for x in ip_value_list:
        file = open("ipvalues.txt",'a')
        file.write(x+'\n')

    DDos_Attack('ipvalues.txt')


#Seeing what Dns requests were made by the user.
def dns_query(packet):
    list = []
    if packet.haslayer(DNSQR):
        dns_value = packet[DNS].qd.qname.decode().rstrip('.')
        list.append(dns_value)
        list_into_set = set(list)
        for x in list_into_set:
            file = open("dnsvalues.txt",'a')
            file.write(x+'\n')

        
sniff(iface='wlan0',prn=src_and_dst)

def malicious_domains():
    file = open('dnsvalues.txt','r')
    dns_content = file.readlines()
    dnsvalues_list = []
    for x in dns_content:
        dnsvalues_list.append(x.rstrip('\n'))

    dnsvalues_set = set(dnsvalues_list)
    print("[*] Started looking for Malicious Domains.")
    for x in dnsvalues_set:
        url = "https://www.virustotal.com/api/v3/domains/"+x
        headers = {
            "accept": "application/json",
            "x-apikey": "68451e7265819cf12ba5c162d3782262a613195843303775dd2139858c216643"
        }

        response = requests.get(url, headers=headers)
        data = response.json()
        if(response.status_code > 399 and response.status_code < 500):
            print("Error in request: "+data['error']['message'])
        print(x+"-",data['data']['attributes']['last_analysis_stats']['malicious'])

malicious_domains()

s = sched.scheduler(time.time, time.sleep)
def malicious_files():

    print("Running at this time ---> ", time.ctime())
    print()
    folder_path = "/home/kali/Desktop/"
    files_before = os.listdir(folder_path)
    for root, dirs,files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root,file)
            with open(file_path,"rb") as f:
                bytes = f.read()
                readable_hash = hashlib.md5(bytes).hexdigest()
                print(f'{file_path} : {readable_hash}')

                url = "https://www.virustotal.com/api/v3/files/"+readable_hash

                header = {
                        "accept":"application/json",
                        "x-apikey":"68451e7265819cf12ba5c162d3782262a613195843303775dd2139858c216643"
                        }
                response = requests.get(url, headers=header)
                data = response.json()
                try:
                    if (data['data']['attributes']['last_analysis_stats']['malicious']) > 0:
                        file = open('maliciousfiles.txt','a')
                        file.write(file_path+'\n')
                        file.write('-'*20+'\n')
                except:
                    file = open('mailiciousfiles.txt','a')
                    file.write("{:16} - Unable to find the Hash. Get this verified by Reverse Engineering the file.".format(file_path)+'\n')
                    file.write('-'*20+'\n')

for i in range(24):
    s.enter(60*i,1,malicious_files,())

s.run()


def ip_of_the_device():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8',80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def send_mail(ip_address):
    msg = MIMEMultipart()
    msg['from'] = 'hackertarun12@gmail.com'
    msg['To'] = "linux.tarun1@gmail.com"
    msg['Subject'] = "Log Report"
    msg.attach(MIMEText(f"Here is the log of the IP {ip_address} address."))

    for filename in ['dnsvalues.txt','ipvalues.txt', 'mailiciousfiles.txt', 'whitelist.txt']:
        with open(filename,"rb") as f:
            attachment = MIMEBase("application","octet-stream")
            attachment.set_payload((f).read())
        encoders.encode_base64(attachment)
        attachment.add_header("Content-Disposition",f"attachemnt;filename={filename}")
        msg.attach(attachment)


    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login("hackertarun12@gmail.com","qbtaflvxnbsxyusa")
    server.sendmail("hackertarun12@gmail.com", "vishalchirumamilla@gmail.com", msg.as_string())
    server.quit()


ip = ip_of_the_device()
send_mail(ip)