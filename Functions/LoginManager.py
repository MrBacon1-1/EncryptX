from Functions.CryptoHandler import CryptoHandler
from Functions.Utilities import Utilities

crypto_handler = CryptoHandler()
utils = Utilities()

class LoginManager():
    def check_login(self, master_pass: str, userdata: str):
        key = crypto_handler.generate_key(master_pass)

        decrypted_password = crypto_handler.decryption(key, userdata["masterpass"]["password"])
        if decrypted_password != None:
            if decrypted_password.decode("utf-8") == master_pass:
                return key
            else:
                return ""


    def create_login(self, master_pass: str, second_entry: str, userdata: str):
        if master_pass != second_entry:
            return ""

        key = crypto_handler.generate_key(master_pass)
        encoded_password = bytes(master_pass, "utf-8")
        encrypted_password = crypto_handler.encryption(key, encoded_password)

        userdata["masterpass"]["password"] = encrypted_password
        utils.save_json(userdata)

        return key