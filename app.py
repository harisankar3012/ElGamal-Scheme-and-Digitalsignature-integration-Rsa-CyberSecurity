from flask import *
from tinyec import registry
import secrets
from Crypto.Cipher import AES
import hashlib, secrets, binascii
import crypto_commons as commons
import random

app = Flask(__name__)

#encoding the values to hexadecimal
def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]
    
curve = registry.get_curve('brainpoolP256r1')

def ecc_calc_encryption_keys(pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = pubKey * ciphertextPrivKey
    return (sharedECCKey, ciphertextPubKey)
    
def ecc_calc_decryption_key(privKey, ciphertextPubKey):
    sharedECCKey = ciphertextPubKey * privKey
    return sharedECCKey

def key_generation():
    privKey = secrets.randbelow(curve.field.n) # alicePrivKey
    temp=privKey
    pubKey = privKey * curve.g    # alicePubKey
    temp2=pubKey
    print("private key:", hex(privKey)) 
    print("public key:", compress_point(pubKey))  
    print(" ")
    (encryptKey, ciphertextPubKey) = ecc_calc_encryption_keys(pubKey)
    print("ciphertext pubKey:", compress_point(ciphertextPubKey))
    print("encryption key:", compress_point(encryptKey))

    decryptKey = ecc_calc_decryption_key(privKey, ciphertextPubKey)
    print("decryption key:", compress_point(decryptKey))

    homedata = { 
    "private key" : hex(privKey), 
    "public key" : compress_point(pubKey),
    "ciphertext pubKey": compress_point(ciphertextPubKey), 
    "encryption key:": compress_point(encryptKey), 
    "decryption key:": compress_point(decryptKey)  
    }
    return homedata
def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)
    

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def encryptMessage(msg):
#     msg = b'Text to be encrypted by ECC public key and decrypted by its corresponding ECC private key'
    msg = bytes(msg,'UTF-8')
    print("original msg:", msg)
    print(" ")
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    encryptedMsg = encrypt_ECC(msg, pubKey)
    #decoding the message
    encryptedMsgObj = {
        'ciphertext': binascii.hexlify(encryptedMsg[0]),
        'nonce': binascii.hexlify(encryptedMsg[1]),
        'authTag': binascii.hexlify(encryptedMsg[2]),
        'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
    }
    return (encryptedMsgObj)
    


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    while e > 0:
        temp1 = temp_phi//e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        x2 = x1
        x1 = x
        d = y1
        y1 = y
    if temp_phi == 1:
        return d + phi

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True


def generate_key_pair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    n = p * q

    # Phi is the totient of n
    phi = (p-1) * (q-1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are coprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)

    # Return public and private key_pair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [pow(ord(char), key, n) for char in plaintext]
    # Return the array of bytes
    return cipher

def decrypt(pk, ciphertext):
    # Unpack the key into its components
    key, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    aux = [str(pow(char, key, n)) for char in ciphertext]
    # Return the array of bytes as a string
    plain = [chr(int(char2)) for char2 in aux]
    return ''.join(plain)

def modInverse(A, M):
    for X in range(1, M):
        if (((A % M) * (X % M)) % M == 1):
            return X
    return -1

def testPrimeness(number):
    for i in range(2, number):
        if number % i == 0:
            return False
            break
    return True

base = 3
p = 1279 #prime
#p = a * q + 1

for i in range(10, p):
    if (p-1) % i == 0 and testPrimeness(i):
        q = i
        break

a = int((p-1)/q)
g = pow(base, a, p) 
x = 15 # private key
y = pow(g, x, p)
print("signing")
k = 10 #random key
h = 123
r = pow(g, k, p) % q
s = modInverse(k, q) * (h + x*r) % q
print("verification")
h = 123
w = modInverse(s, q)
u1 = h * w % q
u2 = r * w % q
v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
if v == r:
    print(" Both are samesignature is valid")
else:
    print("invalid signature is detected")
    



@app.route("/")
def home():
    
    homedata=key_generation();
    #global homedata
    return render_template("index.html",data = homedata);
    
@app.route('/encrypt',methods = ["POST"])
def encrypt1():
    msg = request.form['input_message']
    
    encryptmsg = encryptMessage(msg)
    return render_template("ECC encryption.html",data = encryptmsg,message=msg )
    
@app.route("/back",methods=["POST"])
def back():
    return redirect(url_for('home'))
    
@app.route("/rsa")
def rsa():
    return render_template("RSA.html")
    
@app.route("/rsaa", methods=["POST"])
def rsaa():
    p = int(request.form['prime_number1'])
    q = int(request.form['prime_number2'])
    r = request.form['message1']
    public, private = generate_key_pair(p, q)
    encrypted_msg = encrypt(public, r)
    encrypted_msg=''.join(map(lambda x: str(x), encrypted_msg))
    return render_template("results.html",a=public,b=private,c=encrypted_msg,ram=r)
    
    
if __name__ == "__main__":
    app.run(debug= True)
    
    