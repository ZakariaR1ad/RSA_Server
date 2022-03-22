import imp
import socket
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from matplotlib.pyplot import pause
from RC4 import RC4
from binascii import *

class RSA_System:

    def __init__(self,e,N,d):
        self.e = e
        self.N = N
        self.d = d

    def encrypt(self,msg):
        pt = bytes_to_long(msg)
        ct = pow(pt,self.e,self.N)
        return hex(ct)

    def decrypt(self,cipher):
        ct = int(cipher) #pour preserver la bijectivité du cryptosystème lors de la lecture depuis la console
        pt = pow(ct,self.d,self.N)
        return long_to_bytes(pt)

def generateKeys():
    e = 2**16 -1
    while True:
        p = getPrime(1024)
        q = getPrime(1024)
        if(GCD(p-1,e) ==1  and GCD(q-1,e) == 1): # pour garantir que d existe
            d = pow(e,-1,(p-1)*(q-1))
            return (e,p*q,d)
def exportPublicKey(N,e):
    key = RSA.construct((N,e))
    f = open(r"PubkeyClient.pem","wb")

    f.write(key.exportKey())
    f.close()
    return key.exportKey()





def Menu():
    print("Choose an option.....")
    print("1... Send a message")
    print("2... Receive a message")
    print("3... Exit")
    choice = input("> ")
    try:
        if(float(choice)%1 == 0 and 0<int(choice)<4):
            return int(choice)
        else:
            raise Exception("Something went wrong")
    except:
        raise Exception("Something went wrong")




def Main():
    print("generating key")
    e,N,d = generateKeys()
    rsa = RSA_System(e,N,d)
    PubClient = exportPublicKey(N,e)


    HOST = "127.0.0.1"  # The server's hostname or IP address
    PORT = 1337  # The port used by the server
    pause(5)
    print("connection established")


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        #Key Exchange
        print("Exchanging Keys....")
        PubServer = s.recv(1024)
        PubServer = RSA.importKey(PubServer)
        s.send(PubClient)

        #Receiving the RC4 key
        RC4Key = s.recv(1024)
        RC4Key = rsa.decrypt(bytes_to_long(RC4Key))
        rc4 = RC4(RC4Key)


        while(True):
            choice = Menu()
            match(choice):
                case 1:
                    #Sending a fixed message to the client.
                    s.send(b"1")
                    msg = input("enter your message to encrypt >").encode()
                    enc = rc4.encrypt(msg)
                    s.send(enc.encode())
                case 2:
                    #Receiving a message from the client.
                    s.send(b"2")
                    encrypted_msg = s.recv(1024)
                    print(f"received : {rc4.decrypt(encrypted_msg.decode())}")
                case 3:
                    s.send(b"3")
                    print("GoodBye...!!!")
                    break
Main()
