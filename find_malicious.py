# importing the required libraries.
import sched
import time
import os
import requests
import hashlib
#End of the library calls.

#function for finding the malicious domains visits.
def malicious_domains():
    """This functions checks for the domains requested by the user.
        And then checks with virustotal by making a api call. And tells whether
        the website is malicious or not."""

    #opens the files contains dnsvalues. 
    file = open('dnsvalues.txt','r')
    dns_content = file.readlines()
    #list contains dns values.
    dnsvalues_list = []
    #for loop to append the data in rows.
    for x in dns_content:
        dnsvalues_list.append(x.rstrip('\n'))
    #To remove the duplicates in the domain queries.
    dnsvalues_set = set(dnsvalues_list)
    print("[*] Started looking for Malicious Domains......./")
    print()
    #for loop for finding the malicious domains by making api call.
    for x in dnsvalues_set:
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
        if(response.status_code > 399 and response.status_code < 500):
            print("Error in request: "+data['error']['message'])
        #trh condition to make a log of malicious domains in a text file.
        try:
            print(x+"-",data['data']['attributes']['last_analysis_stats']['malicious'])
            if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                file = open("maliciousdns.txt",'a')
                file.write(x)
        #if the domain is not scanned by the virustotal engines.
        except:
            print("{} - Domain Not Found. Try to Avoid this url.".format(x))
#calling the function.

# malicious_domains()

#scheduling the scan for certain period of time to reduce to usage of ram.
s = sched.scheduler(time.time, time.sleep)

#function for finding the malicious files present in the folders.
def malicious_files_md5():
    """This function will check the files present the directory and sub-directory
        and makes a hash of the files and makes a api call and the sends the hash values
        to find any malicious content."""

    print()
    #defining the folder path.
    folder_path = "/home/kali/Desktop/"
    print("[*] Scanning for Malicious Files {} ---> ".format(folder_path), time.ctime())
    print()
    #for loop for finding the all root directories and sub directories.
    for root, dirs,files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root,file)
            #reads the file contents in binary form.
            with open(file_path,"rb") as f:
                #value of the bytes.
                bytes = f.read()
                #makes a hash of the file which contains the binary values..
                #hash digest of md5
                readable_hash = hashlib.md5(bytes).hexdigest()
                print(f'{file_path} : {readable_hash}')
                #url for making a api call to virustotal.
                url = "https://www.virustotal.com/api/v3/files/"+readable_hash
                #header data to send api value.
                header = {
                        "accept":"application/json",
                        "x-apikey":"68451e7265819cf12ba5c162d3782262a613195843303775dd2139858c216643"
                        }
                #response from virustotal.
                response = requests.get(url, headers=header)
                data = response.json()
                #if the file is malicious writes to the txt.
                try:
                    if (data['data']['attributes']['last_analysis_stats']['malicious']) > 0:
                        file = open('maliciousfiles.txt','a')
                        file.write(file_path+'\n')
                        print(file_path)
                        file.write('-'*20+'\n')
                #if the hash of the file is not available prints warning message.
                except:
                    file = open('maliciousfiles.txt','a')
                    file.write("{:16} - Low \u2717.".format(file_path)+'\n')
                    file.write('-'*20+'\n')

def malicious_files_sha256():
    """This function will check the files present the directory and sub-directory
        and makes a hash of the files and makes a api call and the sends the hash values
        to find any malicious content."""

    print()
    #defining the folder path.
    folder_path = "/home/kali/Desktop/"
    print("[*] Scanning for Malicious Files {} ---> ".format(folder_path), time.ctime())
    print()
    #for loop for finding the all root directories and sub directories.
    for root, dirs,files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root,file)
            #reads the file contents in binary form.
            with open(file_path,"rb") as f:
                #value of the bytes.
                bytes = f.read()
                #makes a hash of the file which contains the binary values..
                #hash digest of md5
                readable_hash = hashlib.sha256(bytes).hexdigest()
                print(f'{file_path} : {readable_hash}')
                #url for making a api call to virustotal.
                url = "https://www.virustotal.com/api/v3/files/"+readable_hash
                #header data to send api value.
                header = {
                        "accept":"application/json",
                        "x-apikey":"68451e7265819cf12ba5c162d3782262a613195843303775dd2139858c216643"
                        }
                #response from virustotal.
                response = requests.get(url, headers=header)
                data = response.json()
                #if the file is malicious writes to the txt.
                try:
                    if (data['data']['attributes']['last_analysis_stats']['malicious']) > 0:
                        file = open('maliciousfiles.txt','a')
                        file.write(file_path+'\n')
                        print(file_path)
                        file.write('-'*20+'\n')
                #if the hash of the file is not available prints warning message.
                except:
                    file = open('maliciousfiles.txt','a')
                    file.write("{:16} - Low \u2717.".format(file_path)+'\n')
                    file.write('-'*20+'\n')

#calling the function for every minute for 24 times.

print("[*] Choose the Encyrption algorithm: ")
print("----> 1. MD5 (32 characters - 128bit)")
print("----> 2. SHA256 (64 characters - 256 bit)")

option = int(input("--->Option: "))

if option == 1:

    for i in range(24):
        s.enter(60*i,1,malicious_files_md5,())
        #running the schedulefile.
        s.run()

elif option == 2:
    for i in range(24):
        s.enter(60*i,1,malicious_files_sha256,())
        #running the schedulefile.
        s.run()

else:
    print("[*] Please provied a valid Input. Either 1 or 2.")

