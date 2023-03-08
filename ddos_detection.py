from collections import Counter


def white_listing_address():
    pass



def DDos_Attack(src_packets):

    file = open(src_packets,'r')
    ip = file.read()
    ip_values_count = Counter(ip.split())
    print(ip_values_count)
    ip_whitelist = []
    file = open('whitelist.txt','r')
    content_list = file.readlines()
    for x in content_list:
        ip_whitelist.append(x.rstrip('\n'))

    for ip_number,ip_count in ip_values_count.items():
        if ip_count>1000 and ip_number not in ip_whitelist:

            print("{} A Ddos attack is detected from this Address. The Activity is been logged.".format(ip_number))

DDos_Attack('ipvalues.txt')