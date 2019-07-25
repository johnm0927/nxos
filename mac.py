#!/usr/bin/env python
mac_entries=[]
with open("c:\software\mac.txt",'rb') as f:
    while True:
        line = f.readline()
        if line:
            #print(line)
            if len(line)<5:
                break
            else:
                mac_entry=line.split()[3]+"."+line.split()[4]
                mac_entries.append(mac_entry)
        else:
            break
f.close()
print("---BD---     -------MAC-------")
for entry in range(0,len(mac_entries)):
    if mac_entries.count(mac_entries[entry])<4:
        print(str(mac_entries[entry].split(".",1)[0]),str(mac_entries[entry].split(".",1)[1]))
        print(mac_entries.count(mac_entries[entry]))
