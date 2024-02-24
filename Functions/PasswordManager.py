import os
import base64
import random
from Functions.CryptoHandler import CryptoHandler

class PasswordManager:
    def __init__(self):
        self.crypto_handler = CryptoHandler()
        
    def get_data(self, key: bytes):
        data = []

        if os.path.isfile("Passwords.encryptx") != True:
            with open("Passwords.encryptx", "w"):
                pass

        with open("Passwords.encryptx", "rb") as read:
            split_data = read.read().split(b"\n")

        for item in split_data:
            if item:
                url_or_program, user, password = item.split(b"04n$b3e0R5K*")
                url_or_program, user, password = base64.b64decode(url_or_program), base64.b64decode(user), base64.b64decode(password)
                url_or_program = self.crypto_handler.decryption(key, url_or_program).decode()
                user = self.crypto_handler.decryption(key, user).decode()
                password = self.crypto_handler.decryption(key, password).decode()
                rating = self.password_rating_check(password)
                data.append([url_or_program, user, password, rating])

        for ind, x in enumerate(data):
            x.insert(0, ind)

        return data

    def add_password(self, url_or_program: str, user: str, password: str, key: bytes):
        password = bytes(password, "utf-8")
        user = bytes(user, "utf-8")
        url_or_program = bytes(url_or_program, "utf-8")
        encrypted_password = (self.crypto_handler.encryption(key, password)).encode("utf-8")
        encrypted_username = (self.crypto_handler.encryption(key, user)).encode("utf-8")
        encrypted_url_or_program = (self.crypto_handler.encryption(key, url_or_program)).encode("utf-8")

        with open("Passwords.encryptx", "ab") as p:
            p.write(base64.b64encode(encrypted_url_or_program) + b"04n$b3e0R5K*" + base64.b64encode(encrypted_username) + b"04n$b3e0R5K*" + base64.b64encode(encrypted_password) + b"\n")

    def remove_password(self, index: int):
        with open("Passwords.encryptX", "rb") as read:
            lines = read.readlines()

        with open("Passwords.encryptX", "wb") as write:
            for index_of_line, line in enumerate(lines):
                if index_of_line != int(index):
                    write.write(line)

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
