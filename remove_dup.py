
def ipvalues():

    file1 = open('ipvalues.txt','r')
    
    ipvalue_set = set()

    for x in file1.read().splitlines():
        ipvalue_set.add(x)

    file2 = open('rd_ipvalues.txt','a')
    for y in ipvalue_set:
        file2.write(y+'\n')

ipvalues()

def dnsvalues():

    file1 = open('dnsvalues.txt','r')
    dnsvalues_set = set()

    for x in file1.read().splitlines():
        dnsvalues_set.add(x)
    file2 = open('rd_dnsvalues.txt','a')
    for y in dnsvalues_set:
        file2.write(y+'\n')

dnsvalues()