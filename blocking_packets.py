import subprocess

blocklist_file = "blocked_domain.txt"

allowed_file = "allowed_domain.txt"

def block_packets():

    file = open(blocklist_file)
    blacklisted = file.read().splitlines()
    for ip in blacklisted:
        print(ip)
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])


def allow_packets():

    file = open(allowed_file)
    blacklisted = file.read().splitlines()
    for ip in blacklisted:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

block_packets()