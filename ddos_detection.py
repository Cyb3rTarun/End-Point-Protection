from collections import Counter



def DDos_Attack(src_packets):

    file = open(src_packets,'r')
    ip = file.read()
    ip_values_count = Counter(ip.split())

    ip_whitelist = []
    content_list = open('whitelist.txt','r')
    for x in content_list.read().splitlines():
        ip_whitelist.append(x)

    for ip_number,ip_count in ip_values_count.items():
        if (ip_count>1000) and (ip_number not in ip_whitelist):

            print("[*] Started Scanning on IP's from Internet..../")
            print("{} A Ddos attack is detected from this Address. The Activity is been logged(\u2713)".format(ip_number))
    


DDos_Attack('ipvalues.txt')