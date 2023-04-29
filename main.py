from Crypto.Util import Counter
from Crypto.Cipher import AES as as_
from Crypto.Util.Padding import pad
from Crypto.Cipher import DES
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization,hashes
from colorama import Fore,Style
import hashlib as hasher
import sys
import os


"""
AES
DES
RSA
SHA
BLOW FİSH # FİX
"""

class colors:
    Red = Fore.RED + Style.BRIGHT #kirmizi
    Gren = Fore.GREEN + Style.BRIGHT #yesil
    blue= Fore.BLUE + Style.BRIGHT # mavi
    yellow= Fore.YELLOW + Style.BRIGHT
    magenta = Fore.MAGENTA + Style.BRIGHT # mor
    cyan = Fore.CYAN + Style.BRIGHT # acik mavi
    white = Fore.WHITE + Style.BRIGHT # beyaz


class DES_:
    def __init__(self):
       self.data = input(f"{colors.magenta}şifrelenecek veri:").encode("utf-8").strip()
       self.__des__()

    def __pad__(self,text:str):
        n = len(text) % 8
        return text + (b' ' * n)

    def __des__(self):
        key = input("creta key enter:").encode("utf-8")
        cipher =  DES.new(key,DES.MODE_ECB)
        enc_ = cipher.encrypt(pad(self.data,DES.block_size))
        print(f"{colors.magenta}[ + ] {colors.blue}DES:", enc_)
        print(f"{colors.magenta}[ + ] {colors.blue}DES KEY :", cipher)

class AES:
    def __init__(self):
        print(f"{colors.magenta}AES Bölümündesiniz.")
        self.data = input(f"{colors.magenta}şifrelenecek veri:").encode("utf-8").strip()
        self.__aes__()

    def __aes__(self):
        # 32 bitlik bir key olşturur
        new_key = os.urandom(32)
        iv = os.urandom(16)
        cr = Counter.new(128, initial_value=int.from_bytes(iv,byteorder='big'))
        cipher = as_.new(new_key, as_.MODE_CTR, counter=cr)
        ciphertext = cipher.encrypt(pad(self.data, as_.block_size))
        print(f"{colors.magenta}[ + ] {colors.blue}AES 128:",ciphertext)
        print(f"{colors.magenta}[ + ] {colors.blue}AES 128 KEY :",new_key)



class RSA:
    def __init__(self):
       print(f"{colors.magenta}RSA Bölümündesiniz.")
       self.data = input(f"{colors.white}şifrelenecek veri:").encode("utf-8").strip()
       self.__crypt__()

    def __crypt__(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        with open("privatekey.pem","wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("public-key.pem","wb") as f:
           f.write(public_key.public_bytes(
               encoding=serialization.Encoding.PEM,
               format=serialization.PublicFormat.SubjectPublicKeyInfo
           ))

        cipher = public_key.encrypt(
            self.data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"{colors.magenta}[ + ] {colors.yellow}RSA:{str(cipher)}")






class SHA:
    def __init__(self):
        print(f"{colors.magenta}SHA-256 Bölümündesiniz.")
        self.data = input(f"{colors.white}şifrelenecek veri giriniz: ")
        self.__has__()

    def __has__(self):
        sha_256 = hasher.sha256()
        sha_256.update(self.data.encode('utf-8'))
        sha256_output = sha_256.hexdigest()
        print(f"{colors.white}[ + ] {colors.magenta}SHA-256 Hash:",sha256_output)




class BruteForceHash:
    def __init__(self):
        print(f"{colors.magenta}Brute Force Bölümndesiniz.")
        self.hash = input("crack hash: ")
        if len(self.hash) != 64:
            print("sha256 giriniz.")
            sys.exit()
        self.__BruteForce__()

    def __BruteForce__(self):
        dosya_yolu = input("Wordlist Giriniz:").strip()
        if os.path.exists(dosya_yolu) == True:
            pass
        else:
            print("dosya bulunamadı kontrol ediniz.")
            sys.exit()
        with open(dosya_yolu,"r") as f:
            for line in f:
                sha__256 = hasher.sha256()
                sha__256.update(line.strip().encode("utf-8"))
                sha_256_output = sha__256.hexdigest()
                if sha_256_output == self.hash:
                    print(f"{colors.magenta}[ + ]{colors.Gren} Found:",line.strip())
                    break
                else:
                    pass




class Main():
    def __init__(self):
        print(f"""{colors.cyan}
▄████████    ▄████████ ▄██   ▄      ▄███████▄     ███      ▄██████▄  
███    ███   ███    ███ ███   ██▄   ███    ███ ▀█████████▄ ███    ███ 
███    █▀    ███    ███ ███▄▄▄███   ███    ███    ▀███▀▀██ ███    ███ 
███         ▄███▄▄▄▄██▀ ▀▀▀▀▀▀███   ███    ███     ███   ▀ ███    ███ 
███        ▀▀███▀▀▀▀▀   ▄██   ███ ▀█████████▀      ███     ███    ███ 
███    █▄  ▀███████████ ███   ███   ███            ███     ███    ███ 
███    ███   ███    ███ ███   ███   ███            ███     ███    ███ 
████████▀    ███    ███  ▀█████▀   ▄████▀         ▄████▀    ▀██████▀  
             ███    ███                                                       
        
        
{colors.Red}[ + ] {colors.magenta}>1< AES 
{colors.Red}[ + ] {colors.magenta}>2< DES 
{colors.Red}[ + ] {colors.magenta}>3< SHA-256  
{colors.Red}[ + ] {colors.magenta}>4< RSA 
{colors.Red}[ + ] {colors.magenta}>5< Brute Force 

{colors.Red}[ - ] DECODE KISMI ÜZERİNDE ÇALIŞYORUM, VERİLERİNİZ SORUMLULUĞUNU ALMIYORUM KULLANAN TARAFA AİTTİR.
        """)
        self.algoritma = int(input(f"{colors.blue}---> Number:"))
        self.__karar__()

    def __karar__(self):
        if self.algoritma > 5:
            print("Seçimi Düzgün Giriniz!")
            sys.exit()

        elif self.algoritma == 1:
            AES()

        elif self.algoritma == 2:
            DES_()

        elif self.algoritma == 3:
            SHA()

        elif self.algoritma == 4:
            RSA()

        elif self.algoritma == 5:
            BruteForceHash()

if __name__=="__main__":
    Main()
