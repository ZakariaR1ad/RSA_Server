import random
from Crypto.Util.number import *


class RC4:
    def __init__(self,Key =random.randbytes(256)):
        #Generation d'une clé aléatoire

        self.Key = Key

    def encrypt(self,M):
        # initialisation
        S = [int(i) for i in range(256)]
        T = [i for i in self.Key]

        #permutations initiales
        j = 0
        for i in range(256):
            j = (j+S[i]+T[i])%256
            S[i], S[j] = S[j],S[i]
        i = 0
        j = 0
        ct = b""
        for m in range(len(M)):
            i = (i+1)%256
            j = (j+S[i])%256
            S[i],S[j] = S[j],S[i]
            t = (S[i]+S[j])%256
            k = S[t]
            ct += long_to_bytes(k^M[m])
        return hex(bytes_to_long(ct))

    def decrypt(self,c):
        ct = long_to_bytes(int(c,16))
        # initialisation
        S = [int(i) for i in range(256)]
        T = [i for i in self.Key]

        #permutations initiales
        j = 0
        for i in range(256):
            j = (j+S[i]+T[i])%256
            S[i], S[j] = S[j],S[i]
        i = 0
        j = 0
        pt = b""
        for c in range(len(ct)):
            i = (i+1)%256
            j = (j+S[i])%256
            S[i],S[j] = S[j],S[i]
            t = (S[i]+S[j])%256
            k = S[t]
            pt += long_to_bytes(k^ct[c])
        return pt



def Menu():
    print("Choose an option....")
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




def Main():
    rc4 = RC4()
    #proof of work
    assert rc4.decrypt(rc4.encrypt(b"hello")) == b"hello"



    print("Hello and Welcome to the RC4 encryption service:")
    while True:
        choice = Menu()
        match(choice):
            case 1:
                pt = input("Enter your plaintext >").strip().encode()
                ct = rc4.encrypt(pt)
                print(f"here's your ciphertext: {ct}")
            case 2:
                ct = input("Enter you ciphertext >").strip().encode()
                pt = rc4.decrypt(ct)
                print(f"here's you plaintext: {pt}")
            case 3:
                print("GoodBye....!!")
                break
if __name__ == "__main__":
    Main()
        
