#Start of importing libraries.
from scapy.layers.dns import DNS,DNSQR
from scapy.layers.inet import IP
from scapy.sendrecv import sniff
#end of library call.

print("[*] Started Looking for Domain Name Queries Made by the User......../")
print("[*] Started Capturing the Network Traffic....../")

#function for looking any domain queries.
def dns_query(packet):
    """This function looks for all the domain queries made by the user."""

    #list for loading the requests.
    list = []
    #if condition for finding the dns request packets.
    if packet.haslayer(DNSQR):
        dns_value = packet[DNS].qd.qname.decode().rstrip('.')
        list.append(dns_value)
        list_into_set = set(list)
        #loop to add the requests made by the user and adding it into the file.
        for x in list_into_set:
            print("[*] Domain Query ----> ",x)
            file = open("dnsvalues.txt",'a')
            file.write(x+'\n')

#function for parsing the sender ip address and receiver ip address.
def src_and_dst(data):
    """Function that tells the sender and reciever ip address."""

    #list of ip sender values.
    ip_value_list = []
    #calling the domain name function.
    dns_query(data)
    
    #for loop for finding and printing the sender and receiver ip address.
    for packet in data:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print("[*] Source --> \033[32m{:15}\033[0m destination --> \033[32m{}\033[0m ".format(src_ip,dst_ip))
            ip_value_list.append(src_ip)        
    #end of for loop.
    # for loop for writing the sender ip address.   
    for x in ip_value_list:
        file = open("ipvalues.txt",'a')
        file.write(x+'\n')
    #end of for loop.

#calling sniff function for start capturing the packets.       
sniff(iface='wlan0',prn=src_and_dst)


