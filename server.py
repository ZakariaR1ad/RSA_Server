
import socket
import random
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from RC4 import RC4

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
        ct = int(cipher,16) #pour preserver la bijectivité du cryptosystème lors de la lecture depuis la console
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
    f = open(r"Pubkey.pem","wb")

    f.write(key.exportKey())
    f.close()


def Menu():
    print("Server starting.....")
    e,N,d = generateKeys()
    rsa = RSA_System(e,N,d)
    exportPublicKey(N,e)
    
    print("Choose a mode: ")
    print("1....Server Mode")
    print("2....Local Mode")
    print("3....Exit")
    choice = input(">")
    try:
        if((float(choice)%1 == 0) and (0 < int(choice) < 4)):
            return int(choice),rsa
        else:
            raise Exception("something went wrong")
    except:
        raise Exception("something went wrong")


def LocalMenu():
    print("Choose an operation: ")
    print("1....Encrypt a message")
    print("2....Decrypt a message")
    print("3....Exit")
    choice = input(">")
    try:
        if((float(choice)%1 == 0) and (0 < int(choice) < 4)):
            return int(choice)
        else:
            raise Exception("something went wrong")
    except:
        raise Exception("something went wrong")

def LocalMode(rsa):
    while(True):
        choice = LocalMenu()
        try: 
            match(choice):
                case 1:
                
                    msg = input("enter your plaintext > ").encode()
                    ct = rsa.encrypt(msg)
                    print(f"here is your ciphertext: {ct}")
                case 2:
                    cipher = input("enter your ciphertext > ").encode()
                    pt = rsa.decrypt(cipher)
                    print(f"here is your plaintext: {pt}")
                case 3:
                    print("GoodBye....!!!")
                    break
        except:
            raise Exception("something went wrong!!!!")




#Partie 3 du tp
def ServerMode(rsa):
    print("Generating RC4 ....")
    print("Waiting for connection....")
    HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
    PORT = 1337  # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        conn, addr = s.accept()
        with conn:
            print(f"Connected to {addr}")
            while True:
                #Echange de clés
                print("Key exchange....")
                f = open("PubKey.pem","rb")
                pubServer= RSA.importKey(f.read())
                conn.send(pubServer.exportKey())

                pubClient = conn.recv(1024)
                pubClient = RSA.importKey(pubClient)

                #Génération d'une clé privé pour RC4
                RC4KEY = random.randbytes(256)
                rc4 = RC4(RC4KEY)

                #envoie de cette clé
                conn.send(long_to_bytes(pow(bytes_to_long(RC4KEY),pubClient.e,pubClient.n)))



                while(True):
                    #Receive the client response
                    choice = conn.recv(1024)
                    match(choice):
                        case b"1":
                            encrypted_msg = conn.recv(1024)
                            print(f"received : {rc4.decrypt(encrypted_msg)}")
                        case b"2":
                            msg = rc4.encrypt(b"Hello there, you still here...")
                            conn.send(msg.encode())
                        case b"3":
                            print("Client is gone....")
                            break



def Main():
    choice,rsa = Menu()
    match(choice):
        case 1:
            ServerMode(rsa)
        case 2:
            LocalMode(rsa)


    
Main()
