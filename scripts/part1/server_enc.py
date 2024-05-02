from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import socket
import os
import random
import string
from Crypto import Random
from Crypto.Cipher import AES

class DHKE():
  def __init__(self):
    self.parameters = dh.generate_parameters(generator=2, key_size=2048)
    self.private_key = self.parameters.generate_private_key()
    self.public_key = self.private_key.public_key()

  def get_public_key(self):
    return self.public_key
  
  def get_peer_public_key(self, peer_public_key_pem):
    peer_public_key = serialization.load_pem_public_key(
      peer_public_key_pem,
      backend=default_backend()
    )
    return peer_public_key

  def get_shared_key(self, peer_public_key):
    shared_key = self.private_key.exchange(peer_public_key)
    derived_key = HKDF(
      algorithm=hashes.SHA256(),
      length=32,
      salt=None,
      info=b'handshake data'
    ).derive(shared_key)
    return derived_key
  
  def get_public_key_pem(self):
    return self.public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
  
class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
    
class Server():
  def __init__(self, host, port):
    self.host = host
    self.port = port
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connectionList = []

    self.key = os.urandom(16)
    self.peer_key = None
    self.dhke = DHKE()
    self.aes = AESCipher(self.key)

    self.sock.bind((self.host, self.port))
    self.sock.listen(1)
    self.main()

  def main(self):
    print(f"Server started on {self.host}:{self.port}")
    while True:
      client_sock, addr = self.sock.accept()
      
      if client_sock not in self.connectionList:
        self.connectionList += [client_sock]
        print(f"Connection from {addr}")
      self.handle_client_connection(client_sock)
    
  def handle_client_connection(self, client_sock): 
    self.peer_key = self.dhke.get_peer_public_key(client_sock.recv(2048))
    client_sock.send(self.dhke.get_public_key_pem())
    shared_key = self.dhke.get_shared_key(self.peer_key)

    while True:
      data = client_sock.recv(2048)
      if not data:
        break
      decrypted_data = self.aes.decrypt(data)
      print(f"Received: {decrypted_data}")
      client_sock.send(self.aes.encrypt("Received"))

if __name__ == "__main__":
  host = "0.0.0.0"
  port = 12345
  server = Server(host, port)
