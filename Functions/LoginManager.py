from Functions.CryptoHandler import CryptoHandler
from Functions.Utilities import Utilities

crypto_handler = CryptoHandler()
utils = Utilities()

class LoginManager():
    def vault_login(self, vault_name: str, master_pass: str):
        key = crypto_handler.generate_key(master_pass)

        with open(f"{vault_name}.encryptx", "r") as r:
            encrypted_password = r.readline()
            r.close()

        decrypted_password = crypto_handler.decryption(key, encrypted_password)
        if decrypted_password.decode("utf-8") == master_pass:
            return key
        else:
            return ""
        

    def create_vault(self, vault_name: str, master_pass: str, second_entry: str):
        if master_pass != second_entry:
            return ""

        key = crypto_handler.generate_key(master_pass)
        encoded_password = bytes(master_pass, "utf-8")
        encrypted_password = crypto_handler.encryption(key, encoded_password)

        with open(f"{vault_name}.encryptx", "w") as w:
            w.write(encrypted_password + "\n")
            w.close()

        return key