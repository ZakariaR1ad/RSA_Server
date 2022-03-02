import socket
from Crypto.PublicKey import RSA
from Crypto.Util.number import *

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 1337  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    s.connect((HOST, PORT))
    # s.sendall(b"Hello, world")
    print("Receiving the public key ....")
    data = s.recv(1024)



    pubKey = RSA.importKey(data)
    N,e = pubKey.n,pubKey.e
    
    #encrypting the message
    msg = input("enter your message to encrypt >").encode()
    enc_msg = hex(pow(bytes_to_long(msg),e,N))[2:]
    
    #send the encrypted message to the server
    s.send(enc_msg.encode())

    #receiving RC4 encrypted data
    data = s.recv(1024)

    print(data)

# print(f"Received {data!r}")