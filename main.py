import os
with open("kargs.txt", 'r', encoding='utf-8-sig') as f:
    a = f.read()
    b=a.split("\n")
    for c in b:
        print("/////////////////////////////////////////////////////////////////////////////////////////////")
        os.system("python pcap.py --pcap "+c)