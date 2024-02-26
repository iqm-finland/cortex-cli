import base64
import tempfile

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = input("Enter password: ").encode()
salt = b'\x05\xd58Y\xfa\x8e\xe1o\xb74=:\x9c\xe9\x82e'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
    )
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)
token = f.encrypt(b"Secret message!")
print("Encrypted message:", token)



password = input("Enter decr password: ").encode()
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
    )
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)
token = f.decrypt(token)
print("Decrypted message:", token)



temp = tempfile.NamedTemporaryFile(prefix='iqm_cortex_cli_token_')
temp.write(token)
temp.seek(0)
print(temp.read())
print(temp.name)
input("Press Enter to continue...")
temp.close()



# from cryptography.fernet import Fernet
# import base64


# def encrypt(text, key):
#     f = Fernet(key)
#     encrypted = f.encrypt(text.encode())
#     return encrypted.decode()


# def decrypt(text, key):
#     f = Fernet(key)
#     decrypted = f.decrypt(text.encode())
#     return decrypted.decode()


# message = "iqm"
# encryption_key = input("Enter the encryption key: ")

# # Ensure the encryption key is in the correct format
# key = base64.urlsafe_b64encode(encryption_key.encode('latin-1'))

# # Encrypt the message
# encrypted_message = encrypt(message, key)
# print("Encrypted message:", encrypted_message)

# # Decrypt the message
# decrypted_message = decrypt(encrypted_message, key)
# print("Decrypted message:", decrypted_message)
