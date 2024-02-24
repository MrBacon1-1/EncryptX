import os
import base64
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class CryptoHandler():
	def generate_key(self, password: str):

		salt = b'~4\xb43\xf6.\xc16P\xc7C\x84\n\xc0\x9e\x96'

		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=1000,
			backend=default_backend()
		)

		key = kdf.derive(password.encode('utf-8'))

		return key

	def encryption(self, key: bytes, plaintext: bytes):
		try:
			iv = os.urandom(16)

			padder = padding.PKCS7(algorithms.AES.block_size).padder()
			plaintext_padded = padder.update(plaintext) + padder.finalize()

			cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

			encryptor = cipher.encryptor()
			ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

			encoded_text = base64.b64encode(iv + ciphertext)

			return encoded_text.decode("utf-8")

		except Exception as e:
			print("Error Encrypting! " + str(e))

	def decryption(self, key: bytes, ciphertext: bytes):
		try:
			ciphertext = base64.b64decode(ciphertext)

			iv = ciphertext[:16]

			cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
			decryptor = cipher.decryptor()

			decrypted_padded = decryptor.update(ciphertext[16:]) + decryptor.finalize()

			unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
			decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()

			return decrypted_text

		except Exception as e:
			print("Error Decrypting! " + str(e))
