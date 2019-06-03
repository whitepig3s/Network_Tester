#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from  scapy.all import *
import netifaces
import datetime
import ipaddress
import pandas as pd
from subprocess import run

print ("Testing...") 
start_time=datetime.datetime.now()

'''LINK STATUS'''
carrier=open('/sys/class/net/eth0/carrier','r') 
connect=carrier.readline()
print("Link Status")
if (connect=='0\n'):
    print ("operstate: down\n")
else:
    print ("operstate: up\n")
        
    '''IP state'''
    interface=open('/etc/network/interfaces','r')
    state=interface.readlines()
    static=False
    for i in state:
        if (0<i.find("static")):
            static=True
    if (static==True):        
        print("IP state: Static")
    else:
        print("IP state: DHCP")
            
    '''print network_inf'''
    try:
        addr=netifaces.ifaddresses('eth0')[2][0]['addr']
        netmask=netifaces.ifaddresses('eth0')[2][0]['netmask']
        gateway=netifaces.gateways()[2][0][0]
        network_inf = "Address: %s\nNetmask: %s\nGateway: %s\n"%(addr,netmask,gateway)
        print (network_inf)
    except:
        print ('no information about network\n')
        '''search IP'''
        catch =sniff (iface='eth0',filter ="ip and udp port 1900 or arp" ,count=100,timeout=30)
        lenth=len(catch)
        data=[]
        num=[]
        arp=[]
        def check_ip (ip_addr):
            if (ip_addr!="0.0.0.0" and ip_addr!="255.255.255.255"):
                tmp=int(ipaddress.IPv4Address(ip_addr))
                if (tmp<=3758096384): #CLASS D,E
                    if (tmp>2851995648 and tmp<2852061183): #169.254.0.0/16
                        return False
                    else:
                        return True
                else:
                    return False
            else:
                return False

        for i in range(lenth):
            if (int(catch[i][0].type)==2048):
                if (check_ip(catch[i][IP].src)==True):
                    tmp=catch[i][IP].src
                    data.append(tmp)
                    num.append(int(ipaddress.ip_address(tmp)))
            elif (int(catch[i][0].type)==2054):
                if (check_ip(catch[i][ARP].psrc)==True):
                    tmp=catch[i][ARP].psrc
                    arp.append(tmp)
                    data.append(tmp)
                    num.append(int(ipaddress.ip_address(tmp)))
                if (check_ip(catch[i][ARP].pdst)==True):
                    dst=catch[i][ARP].pdst
                    arp.append(dst)
        '''list to dataframe'''
        data={'number':num,'ip_address':data}
        data=pd.DataFrame(data)
        data=data.drop_duplicates('ip_address',keep='first',inplace=False)
        data=data.sort_values(by='number')

        '''calculate mask'''
        last=(data.iloc[-2]).number
        first=(data.iloc[1]).number
        mask_fl=((last&first)|(~(last|first)))
        mask_c=mask_fl+256**4
        mask_c=str(ipaddress.IPv4Address(int (mask_c)))
        mask=0
        for i in range(2,31):
            tmp="255.255.255.255/" + str(i)
            tmp=ipaddress.ip_network(tmp,strict=False)
            if(ipaddress.IPv4Address(mask_c)<tmp.netmask):
                mask=i-1
                break
        mask_str=ipaddress.ip_network("255.255.255.255/" + str(mask),strict=False)

        '''calculate GW'''
        dict={}
        maxaddr=0
        GW=''
        for key in arp:
            dict[key]=dict.get(key,0)+1
            if (maxaddr<dict[key]):
                maxaddr=dict[key]
                GW=key

        '''calculate IP'''
        for i in range (0,len(data)-1):
            ip=0
            if (((data.iloc[i]).number-(data.iloc[i+1]).number)<1):
                ip=((data.iloc[i]).number)+1
                break

        print("Result")
        print ("IP address:",end=" ")
        print (ipaddress.ip_address(int (ip)))
        print ("Network mask:",end=" ")
        print(mask_str.netmask)
        print ("Gateway:",end=" ")
        print (GW)
        
    '''Ping GW and Google'''
    def result (ping_result):
        if (ping_result>=9):
            print ("Sucess")
        else:
            print ("Failed")
    
    print ("Ping Gateway...")
    try:
        ping_gw='ping '+gateway+" -c 10"
        gw_test=subprocess.getoutput(ping_gw)
        ping_gw_result=(gw_test.split(','))[1]
        ping_gw_result=int(ping_gw_result.split(' ')[1])
    except:
        pass
    result(ping_gw_result)
    
    print ("Ping Google...")
    try:
        google_test=subprocess.getoutput("ping 8.8.8.8 -c 10")
        ping_google_result=(google_test.split(','))[1]
        ping_google_result=int(ping_google_result.split(' ')[1])
    except:
        pass
    result(ping_google_result)
    
print("\nFinished Test.\n")

'''Testing time'''
end_time=datetime.datetime.now()
print ("Testing Time:",end=' ')
print ((end_time-start_time).seconds,end=".")
print ((end_time-start_time).microseconds//10000,end=" ")
print ("seconds")

