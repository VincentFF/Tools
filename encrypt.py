import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher:

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
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


if __name__ == "__main__":
    key =  input("Enter you key:\n")
    aes = AESCipher(key)
    select = input("input: 1 for encrypt, 2 for decrypt:\n")
    if select == "1":
        passwd = input("enter your encrypting passwd:\n")
        encrypt_passwd = aes.encrypt(passwd)
        print("encrypted passwd:", encrypt_passwd)
    elif select == "2":
        encrypt_passwd = input("enter your encrypted passwd:\n")
        print("decode passwd:\n", aes.decrypt(encrypt_passwd)) 
    else:
        print("input error.")
    
    
    
    
    