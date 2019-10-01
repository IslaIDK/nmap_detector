
from time import ctime,sleep
import threading
import subprocess
import os
host_addr = "192.168.1.100"
public_ip = "81.215.137.136"
src_ips_ports = []
dest_ips_ports = []
ips_services = {}
c_types = []
mesg = []
ips = []
services = []
checking= []
clean_list= []
WARNING = '\033[93m'
CLEAN = '\033[92m'
BOLD = '\033[1m'
ENDC = '\033[0m'
nmap = "" # fix this
nmap_detect = ""

def main():
    global checking
    global clean_list
    global mesg
    global WARNING
    global ENDC
    global nmap
    global nmap_detect
    print(WARNING +"Note each time you run me the results text file will lose all the information \n\n"+ '\x1b[0m')
    print(WARNING +"Note results will be found in results text file \n\n"+ '\x1b[0m')
    print(WARNING +"Note sniffing may take time up to 10 sec for each time"+ '\x1b[0m')
    os.system('gnome-terminal -- sudo python3 keep.py >/dev/null 2>&1')
    while True:
        os.system('gnome-terminal -- sudo python3 sniff.py >/dev/null 2>&1')
        sleep(10)
        f= open("textout.txt","r+")
        for i in f:
            a = i.split(" ")
            conn_type(a) # has TCP UDP APR
            src_ip_port(a)
            dest_ip_port(a)

        try:

            for x in range(0,len(src_ips_ports),2):#,dest_ips_ports[x],dest_ips_ports[x+1]
                                                    #\nConnection to {} using this port {}
                print("\nConnection from {} using  {} \nConnection to {} using {}\n===============================================\n".format(src_ips_ports[x],src_ips_ports[x+1],dest_ips_ports[x],dest_ips_ports[x+1]))
                    # fix from to ip
                if len(nmap_detect) > 4:
                    print("len was 4")
                    print("Possible to be Nmap scan")
                    mesg = []
                else:
                    pass
        except:
            pass
        f.close()
def nmap_d(ip_service):
    print(" nmap_d(ip_service) got called")
    global nmap_detect
    global ips_services
    global mesg
    ips, services = ip_service.split(":")
    try:#it will return KeyError if ips not in ips_services so i used try to avoid erorrs
        print("im in try now")
        if ips_services[ips]:
            print("im in if now")
            info = ips_services[ips]
            print(ips_services[ips])
            print(len(ips_services[ips]))
            try:
                if len(info) >4: # if the service for one ip is more than 5 it will show the mesg
                    with open("results.txt" ,"a") as info:
                        info.write("\n\t\t\tPossible to be an Nmap  or any other scan\n\n{} \n\nservices {}\n\n================================================\n\n".format(ips,ips_services[ips]))
            except:
                print(len(info))
            if services in info:
                ips_services.update({ips:(services)}) # keep passing the (services) as tuple so it will be easy to count them later
            elif not services in info:
                info.append(services)
                ips_services.update({ips:(info)})
    except:# not pass the [services] first time as list
        ips_services[ips]=[services]
        if ips_services[ips]:
            info = ips_services[ips]
def dest_ip_port(data):
    global nmap
    for i in data[8:9]:
        p = i.split(":")
        if len(p) ==2:
            ip_dest,port_dest = p
            if ip_dest.find(".") < 1 or 2:
                dest_ips_ports.append(ip_dest)
                a = check(ip_dest)
                if a == 1:
                    check_status = True
                else:
                    pass
            if len(port_dest) > 0:
                try:
                    if str.isdigit(port_dest):
                        dest_ips_ports.append(port_dest)
                    elif not str.isdigit(port_dest):
                        dest_ips_ports.append(" >> [-]service {}".format(port_dest))
                        ip_service =("{}:{}".format(ip_dest,port_dest))
                        nmap_d(ip_service)
                except:
                    pass
            else:
                dest_ips_ports.append("None")
        else:
            pass
def src_ip_port(data):
    try:
        if len(clean_list) == 0:
            clean_list.append(host_addr)
            clean_list.append(public_ip)
    except:
        pass
    for i in data[6:7]:
        p = i.split(":")
        if len(p) ==2:
            ip_src,port_src = p
            if ip_src.find(".") < 1 or 2:
                src_ips_ports.append(ip_src)
                a = check(ip_src)
                if a == 1:
                    check_status = True
                else:
                    pass
            if len(port_src) > 0:
                try:
                    if str.isdigit(port_src):
                        data = int(port_src)
                        src_ips_ports.append(port_src)
                    elif not str.isdigit(port_src):
                        src_ips_ports.append(" >> [-]service {}".format(port_src))
                        ip_service =("{}:{}".format(ip_src,port_src))
                        nmap_d(ip_service)

                except:
                    pass
            else:
                src_ips_ports.append("None")
        else:
            pass
def check(ip_src):
    global mesg
    global h
    mesg = None
    #converting <src_ips_ports> into str to look into it as string
    cc = " ".join(src_ips_ports)
    check = cc.find(ip_src)
    clean = is_it_clean(ip_src)
    ips_checking = checking.count(ip_src)
    checking.append(ip_src)
    if clean == 1:
        return
    elif ips_checking >7: ## add what should i do here later !! and change 7 to what user wants
        mesg = [ips_checking,ip_src]
def is_it_clean(ip):
    if clean_list.count(ip) < 1:
        pass
    elif clean_list.count(ip) > 1:
        try:
            checking.remove(ip)
            clean_status = True
            return 1
        except:
            pass
        with open("clean.txt","r") as clean_ips:
            if ip in clean_ips.read():
                clean_status = True
                return 1
            else:
                pass
        with open("clean.txt","a") as clean_ips:
            clean_ips.write(ip)
        inside_clean = clean_list.count(ip)
        print("inside_clean",inside_clean)
def conn_type(data):
        type = data[5:6]
        c_type = "".join(type)

        if c_type == "TCP":
                c_types.append(c_type)
        if c_type == "UDP":
                c_types.append(c_type)
        if c_type != "TCP" or "UDP":
            type = data[4:5]
            c_type = "".join(type)
            if c_type == "ARP":
                arp_list.append("An ARP got ignornt {} <<{}>>".format(c_type,ctime()))

        else:
            type = None
with open("results.txt" ,"w") as re:
    re.write("")
with open('textout.txt' ,"w") as ccc:
    ccc.write("")
main()
