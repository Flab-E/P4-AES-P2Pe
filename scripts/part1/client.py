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

  
class Client():
  def __init__(self, host, port):
    self.host = host
    self.port = port
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    self.dhke = DHKE()

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
    public_key = self.dhke.generate_public_key()

    start = time.time()
    self.sock.connect((self.host, self.port))
    self.sock.send(public_key.encode())
    self.logger.info(f"Public Key: {public_key}")

    peer_key = self.sock.recv(2048).decode()
    self.logger.info(f"Peer Key: {peer_key}")

    self.key = self.dhke.generate_shared_key(peer_key)
    # print(f"Key: {self.key}")
    self.logger.info(f"Key: {self.key}")
    end = time.time()
    self.logger.info(f"Time taken for key exchange: {end - start}")

    self.key = self.key[:16]
    print('------------------>', len(self.key))
    self.aes = AESCipher(self.key)

    for i in range(5):
      start_enc = time.time()
      # random ascii string of length 10
      message = ''.join(random.choices(string.ascii_letters, k=32))
      self.sock.send(self.aes.encrypt(message))
      end_enc = time.time()
    #   print(f"Time taken for enc: {end_enc - start_enc}")
      self.logger.info(f"Time taken for encrypting message: {end_enc - start_enc}")

      start_dec = time.time()
      data = self.sock.recv(2048)
    #   print(f"Received: {self.aes.decrypt(data)}")
      self.logger.info(f"Received: {self.aes.decrypt(data)}")
      end_dec = time.time()
    #   print(f"Time taken for dec: {end_dec - start_dec}")
      self.logger.info(f"Time taken for decrypting message: {end_dec - start_dec}")

    end = time.time()
    # print(f"Time taken: {end - start}")
    self.logger.info(f"Total Time taken: {end - start}")

if __name__ == "__main__":
  host = "192.168.1.10"
  port = 12345
  client = Client(host, port)
