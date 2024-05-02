from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64

import socket
import time
import random
import string
import logging

from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128
from Crypto.Protocol.DH import key_agreement

class DHKE:
    def __init__(self):
        self.private_key = ECC.generate(curve='p256')
        self.public_key = self.private_key.public_key()

    def generate_public_key(self):
        return self.public_key.export_key(format='PEM')

    def generate_shared_key(self, peer_public_key):
        peer_key = ECC.import_key(peer_public_key)
        shared_key = key_agreement(static_priv=self.private_key, static_pub=peer_key, kdf=self.kdf)
        return shared_key

    def kdf(self, x):
        return SHAKE128.new(x).read(32)


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        plaintext = pad(plaintext, 16).encode()
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv
        print(plaintext, AES.block_size)
        ct_bytes = cipher.encrypt(plaintext)
        ct = base64.b64encode(iv + ct_bytes)
        return ct

    def decrypt(self, ct):
        ct = base64.b64decode(ct)
        iv = ct[:16]
        ct_bytes = ct[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ct_bytes), AES.block_size)
        return plaintext

# Helper functions for padding and unpadding
def pad(s, bs):
    if isinstance(s, bytes):
        s = s.decode('utf-8')  # Decode bytes to string
    padded_string = s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
    if isinstance(s, bytes):
        padded_string = padded_string.encode()  # Encode string back to bytes
    return padded_string

def unpad(s, bs):
    unpadded_string = s[:-ord(s[-1:])]
    return unpadded_string

  
class Server():
  def __init__(self, host, port):
    self.host = host
    self.port = port
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connectionList = []

    self.dhke = DHKE()

    self.sock.bind((self.host, self.port))
    self.sock.listen(1)

    self.logger_setup()
    self.main()

  def logger_setup(self):
    logging.basicConfig(level=logging.DEBUG)
    self.logger = logging.getLogger(__name__)
    self.logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler('server.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    self.logger.addHandler(file_handler)

  def main(self):
    # print(f"Server started on {self.host}:{self.port}")
    self.logger.info(f"Server started on {self.host}:{self.port}")
    while True:
      client_sock, addr = self.sock.accept()
      
      if client_sock not in self.connectionList:
        self.connectionList += [client_sock]
        print(f"Connection from {addr}")
        self.logger.info(f"Connection from {addr}")
      self.handle_client_connection(client_sock, addr)
    
  def handle_client_connection(self, client_sock, addr): 
    start = time.time()
    public_key = self.dhke.generate_public_key()
    peer_key = client_sock.recv(2048).decode()
    self.key = self.dhke.generate_shared_key(peer_key)
    client_sock.send(public_key.encode())

    self.logger.info(f"\t{addr}\Peer Key: {peer_key}")
    self.logger.info(f"\t{addr}\tPublic Key: {public_key}")
    self.logger.info(f"\t{addr}\tKey: {self.key}")
    
    end_key_share_time = time.time()
    self.logger.info(f"\t{addr}\tKey share time: {end_key_share_time - start}")
    
    self.aes = AESCipher(self.key)

    while True:
      start_decryption = time.time()
      data = client_sock.recv(2048)
      if not data:
        break
      decrypted_data = self.aes.decrypt(data)
    #   print(f"Received: {decrypted_data}")
      self.logger.info(f"\t{addr}\tReceived: {decrypted_data}")
      end_decryption = time.time()
      self.logger.info(f"\t{addr}\tDecryption time: {end_decryption - start_decryption}")
    #   print(f"Decryption time: {end_decryption - start_decryption}")

      start_encryption = time.time()
      client_sock.send(self.aes.encrypt("Received"))
      end_encryption = time.time()
      self.logger.info(f"\t{addr}\tEncryption time: {end_encryption - start_encryption}")

    self.logger.info(f"\t{addr}\tTotal Time: {time.time() - start}")
    # print(f"Total Time: {time.time() - start}")


if __name__ == "__main__":
  host = "0.0.0.0"
  port = 12345
  server = Server(host, port)
