import gc
import base64
import random
from CTkMessagebox import CTkMessagebox
from Functions.CryptoHandler import CryptoHandler
from Functions.Utilities import Utilities

crypto_handler = CryptoHandler()
utils = Utilities()

class PasswordManager:      
    def get_data(self, vault_path: str):
        if not utils.check_vault_status(vault_path):
            print("Get Data >> Vault Not Found!")
            return

        data = []

        with open(vault_path, "rb") as r:
            r.readline()
            split_data = r.read().split(b"\n")
            r.close()

        for item in split_data:
            if item:
                url_or_program, user, password = item.split(b":")
                url_or_program, user, password = base64.b64decode(url_or_program), base64.b64decode(user), base64.b64decode(password)
                data.append([url_or_program, user, password])

        for ind, x in enumerate(data):
            x.insert(0, ind)

        return data


    def add_password(self, vault_path: str, url_or_program: str, user: str, password: str, key: bytes):
        if not utils.check_vault_status(vault_path):
            print("Add Password >> Vault Not Found!")
            return
        
        password = bytes(password, "utf-8")
        user = bytes(user, "utf-8")
        url_or_program = bytes(url_or_program, "utf-8")
        encrypted_password = (crypto_handler.encryption(key, password)).encode("utf-8")
        encrypted_username = (crypto_handler.encryption(key, user)).encode("utf-8")
        encrypted_url_or_program = (crypto_handler.encryption(key, url_or_program)).encode("utf-8")

        with open(vault_path, "ab") as p:
            p.write(base64.b64encode(encrypted_url_or_program) + b":" + base64.b64encode(encrypted_username) + b":" + base64.b64encode(encrypted_password) + b"\n")


    def remove_password(self, vault_path: str, tree: str, index: int, key: bytes):
        if not utils.check_vault_status(vault_path):
            print("Remove Password >> Vault Not Found!")
            return

        with open(vault_path, "rb") as r:
            password = r.readline()
            lines = r.readlines()
            r.close()

        with open(vault_path, "wb") as w:
            w.write(password)
            for index_of_line, line in enumerate(lines):
                if index_of_line != int(index):
                    w.write(line)
            w.close()

        self.refresh_treeview(vault_path, tree, key)


    def password_rating_check(self, password: str):
        score = 0
        lowercase_characters_present = uppercase_characters_present = special_characters_present = numbers_present = False

        lowercase_characters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
        uppercase_characters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        special_characters = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '[', ']', '{', '}', '|', '\\', ';', ':', "'", '"', ',', '.', '<', '>', '/', '?']
        numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

        for char in lowercase_characters:
            if char in password:
                lowercase_characters_present = True
        for char in uppercase_characters:
            if char in password:
                uppercase_characters_present = True
        for char in special_characters:
            if char in password:
                special_characters_present = True
        for char in numbers:
            if char in password:
                numbers_present = True

        if lowercase_characters_present == True:
            score += 1
        if uppercase_characters_present == True:
            score += 1
        if special_characters_present == True:
            score += 1
        if numbers_present == True:
            score += 1
        if len(password) >= 8:
            score += 1

        return score


    def password_generator(self, length: int, special: bool):
        if special == "yes":
            characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%^&*()"
        else:
            characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
        generated_password = ""
        for i in range(length):
            generated_password += random.choice(characters)

        return generated_password
    

    def refresh_treeview(self, vault_path: str, tree: str, key: bytes):
        if not utils.check_vault_status(vault_path):
            print("Refresh Tree >> Vault Not Found!")
            return

        for item in tree.get_children():
            tree.delete(item)

        data = self.get_data(vault_path)
        for line in data:
            modified_line = list(line)
            modified_line[1] = crypto_handler.decryption(key, modified_line[1]).decode()
            modified_line[2] = crypto_handler.decryption(key, modified_line[2]).decode()
            modified_line.append(self.password_rating_check(crypto_handler.decryption(key, modified_line[3]).decode()))
            modified_line[3] = "••••••••"
            modified_line = tuple(modified_line)
           
            tree.insert("", "end", values=modified_line)

            del modified_line
            gc.collect()