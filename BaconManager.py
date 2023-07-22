import os
import colorama
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import time
import keyboard
from tabulate import tabulate
import pyperclip
import random


MAIN_MENU = f"""                                                        
                                         _____                    _____                         
                                        | __  |___ ___ ___ ___   |     |___ ___ ___ ___ ___ ___ 
                                        | __ -| .'|  _| . |   |  | | | | .'|   | .'| . | -_|  _|
                                        |_____|__,|___|___|_|_|  |_|_|_|__,|_|_|__,|_  |___|_|   Ver. 1.0
                                                                                   |___|        
                                                                                                   
                                                                            |
                                                                            |          <Options>
                                              :.                            |
                                            :P!7?7:                         |
                                            P!::^77?!                       |           1 ~> View Passwords
                                           ~P:::~!:.#G^                     |
                                          :P^::~!~.^BJB^                    |           2 ~> Add Password
                                         !5^::~!!:.JG?55                    |
                                     .^7J!::^~!!:.~BJ?G?                    |           3 ~> Remove Password
                                 .~7?7!^^^~!!!^..7GJ?JB.                    |
                               ^J?~^^^~!!!!^:..~5PJ?JB^ 77^                 |           4 ~> Password Generator
                              7Y^:^~!!!~^:.:~?55J?J5G~^5~^YY                |
                             ~P::~!!~^..:!Y55YJJY557.7Y^^~~JP               |           5 ~> Join My Discord Server
                            .G^:^!!^..!5PYJJJYYJ7^.~Y!:^!!!!?5              |           
                            P7:^!!:.^PPJ?YPBGJ!~~7?!^^~!!!!^.PY             |           6 ~> Exit
                          ~5!:^~!:.~BY?JG5!~~~~~~^^^~!!!!~:.YP#.            |   
                     .:~7?7^:^~!^..BY?JBY~~!!!!!!!!!!!!!^.:5P5G             |            
                .^7??7!~^:^^~!!~..5P??GP~!!!!!!!!!!!!~^..7P5PJ              |          <Key Binds>
             .!?7~^^^^^~~!!!!~:..JGJ?5P::::::::::::...:75P5P^               |           
           .JJ~::^~~!!!!~~^:..:7P5??5B7!7??777!!!!!7?YPPP5~                 |            
         :5B~:^~!!!!~^:.:^!7JY5YJ?YGBPY555555555PPPPP5Y7:                   |           Ctrl + E ~> Exit
        ?JP?:~!!!!^..^?Y555YYYYYP#GYJY5Y7~^^^~~!!~~:.                       |            
        B^55~!!!~..^5PYJY5YJ?!~7G5?YP7.                                     |             
        YY!PP7!~..7GY?5BJ~^^^!YPJYP?.                                       |            
         G7^~J5!.~BJ?5B5YY555YY55?.                                         |
         .P:.7GP5#GJJBGYYY555Y?^                                            |
          :PG5?YP?~JY?.:^^:.                                                |
           .55P5.                                                           |
             ..                                                             |
                                                                            |   


"""
def encryption(key, plaintext):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext

def decryption(key, ciphertext):
    cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def exit_bind():
   pid = os.getpid()
   os.system(f"taskkill /F /PID {pid}")

def get_passwords():
    ready_data = []

    with open("Passwords.txt", "rb") as read:
        split_data = read.read().split(b"\n")
        read.close()

    for data in split_data:
        if data:
            url_or_program_ciphertext, user_ciphertext, password_ciphertext = data.split(b"04n$b3e0R5K*")
            url_or_program = decryption(key, url_or_program_ciphertext).decode()
            user = decryption(key, user_ciphertext).decode()
            password = decryption(key, password_ciphertext).decode()
            ready_data.append([url_or_program, user, password])
            
    for ind, x in enumerate(ready_data):
        x.insert(0, ind) 
    
    table_to_print = tabulate(ready_data, headers=["Index", "Name", "Username", "Password"], tablefmt="double_grid")
    
    lenght = len(table_to_print.split("\n")[0])
    
    os.system(f"cls && mode con:cols={lenght} lines=9999")
    print(colorama.Fore.LIGHTCYAN_EX + table_to_print + colorama.Fore.RESET)
    input()

    if style == "cli":
       main_cli()
    elif style == "gui":
       main_gui()

def add_password(url_or_program, user, password):
    encrypted_password = encryption(key, password)
    encrypted_username = encryption(key, user)
    encrypted_url_or_program = encryption(key, url_or_program)

    with open("Passwords.txt", "ab") as p:
        p.write(encrypted_url_or_program + b"04n$b3e0R5K*" + encrypted_username + b"04n$b3e0R5K*" + encrypted_password + b"\n")            
       
def remove_password(index):
   with open("Passwords.txt", "rb") as read:
      lines = read.readlines()
      print(lines)
      read.close()
   with open("Passwords.txt", "wb") as write:
      for index_of_line, line in enumerate(lines):
         if index_of_line != int(index):
            print(index_of_line)
            write.write(line)

   input()

   if style == "cli":
      main_cli()
   elif style == "gui":
      main_gui()

def main_cli():
    os.system("cls")
    os.system(f"title Bacon Manager v1.0 ~ Logged In As {username} ")
    os.system("mode con:cols=144 lines=42")
    print(colorama.Fore.LIGHTCYAN_EX + MAIN_MENU + colorama.Fore.RESET)
    opt = input(colorama.Fore.LIGHTCYAN_EX + "  BaconManager/Console/.. " + colorama.Fore.RESET)

    if opt == "":
       print(colorama.Fore.RED + "  !Invlid Option!" + colorama.Fore.RESET)
       time.sleep(1)
       main_cli()

    elif opt == "1":
       get_passwords()
       main_cli()

    elif opt == "2":
       os.system("cls & mode con:cols=80 lines=16")
       print(colorama.Fore.RED + "Your username or password must not contain '|' or '~'.\nYour name, username or password must not be longer than 50.\n" + colorama.Fore.RESET)
       url_or_program = input(colorama.Fore.LIGHTCYAN_EX + "\nWebsite Or Program Name ~> " + colorama.Fore.RESET)
       user = input(colorama.Fore.LIGHTCYAN_EX + "Username ~> " + colorama.Fore.RESET)
       password = input(colorama.Fore.LIGHTCYAN_EX + "Password To Store ~> " + colorama.Fore.RESET)
       if "|" in password or "~" in password:
         main_cli()
       if len(password) > 50 or len(user) > 50 or len(url_or_program) > 50:
         main_cli()
       add_password(url_or_program, user, password)
       main_cli()

    elif opt == "3":
       os.system("cls & mode con:cols=80 lines=16")
       index = input(colorama.Fore.LIGHTCYAN_EX + "\nIndex Of Password To Remove ~> " + colorama.Fore.RESET)
       remove_password(index)
       main_cli()

    elif opt == "4":
       os.system("cls & mode con:cols=80 lines=16")
       while True:
         length = int(input(colorama.Fore.LIGHTCYAN_EX + "Enter Password Lenght ~> " + colorama.Fore.RESET))
         characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%^&*()"
         generated_password = ""
         for i in range(length):
            generated_password += random.choice(characters)
         print(colorama.Fore.LIGHTCYAN_EX + f"Password ~> {generated_password}" + colorama.Fore.RESET)
         opt = input(colorama.Fore.LIGHTCYAN_EX + "Use this password (Y/N) ~> " + colorama.Fore.RESET)
         if opt.lower() == "y":
            pyperclip.copy(generated_password)
            print(colorama.Fore.LIGHTCYAN_EX + "Password Copied To Your Clip Board!" + colorama.Fore.RESET)
            time.sleep(2)
            break
         else:
            continue
       main_cli()

    elif opt == "5":
       os.system("start https://discord.gg/cf9mxTgDFa")
       main_cli()

    elif opt == "6":
       exit()
       
    else:
       print(colorama.Fore.RED + "  !Invlid Option!" + colorama.Fore.RESET)
       time.sleep(1)
       main_cli()

    main_cli()

def main_gui():
    # Not Done
    input("Work In Progress")
    exit()

def login_creation_cli():
    global key, username

    os.system("cls & title Bacon Manager v1.0 ~ Account Creation")
    print(colorama.Fore.RED + "\nYour username & password must be minimum 8 characters long!\nYour username or password must not contain '|' or '~'\nYour username or password must not be longer than 50.\n" + colorama.Fore.RESET)
    username = input(colorama.Fore.LIGHTCYAN_EX + "Username ~> " + colorama.Fore.RESET)
    master_pass = input(colorama.Fore.LIGHTCYAN_EX + "Enter Your Master Password ~> " + colorama.Fore.RESET)
    second_entry = input(colorama.Fore.LIGHTCYAN_EX + "Re-Enter The Password ~> " + colorama.Fore.RESET) 
    if len(username) < 8:
      login_creation_cli()
    if len(master_pass) < 8 or master_pass != second_entry:
      login_creation_cli()
    if "|" in master_pass or "~" in master_pass:
      login_creation_cli()
    if len(master_pass) > 50 or len(username) > 50:
      login_creation_cli()

    key = username[0:8] + master_pass[0:8]
    encrypted_password = encryption(key, master_pass)
    hash_password = hashlib.md5(encrypted_password).hexdigest()
    with open("UserData.txt", "w") as w:
       w.write(f"{username}04n$b3e0R5K*{hash_password}")
       w.close()

    if style == "cli":
       main_cli()
    if style == "gui":
       main_gui()

def login_cli():
    global username, key

    os.system(f"title Bacon Manager v1.0 & mode con:cols=80 lines=16")
    os.system("cls")
    username = input(colorama.Fore.LIGHTCYAN_EX + "\nUsername ~> " + colorama.Fore.RESET)
    master_pass = input(colorama.Fore.LIGHTCYAN_EX + "Enter Your Master Password ~> " + colorama.Fore.RESET)

    if len(master_pass) < 8 or len(username) < 8:
      print(colorama.Fore.RED + "\n   !Invalid Login!" + colorama.Fore.RESET)
      time.sleep(2)
      login_cli()

    key = username[0:8] + master_pass[0:8]
    encrypted_password = encryption(key, master_pass)
    hash_password = hashlib.md5(encrypted_password).hexdigest()

    with open("UserData.txt", "r") as r:
       userdata = r.read().split("\n")
       r.close()
    
    for user in userdata:
       if user.split("04n$b3e0R5K*")[0] == username and user.split("04n$b3e0R5K*")[1] == hash_password:
          if style == "cli":
             main_cli()
          elif style == "gui":
             main_gui()
             
    print(colorama.Fore.RED + "\n   !Invalid Login!" + colorama.Fore.RESET)
    time.sleep(2)
    login_cli()

def boot():
    global style

    keyboard.add_hotkey('Ctrl+E', exit_bind)

    os.system(f"title Bacon Manager v1.0 & mode con:cols=80 lines=16")
    boot = input(colorama.Fore.LIGHTCYAN_EX + "Would you like to use CLI or GUI? " + colorama.Fore.RESET)
    if boot.lower() == "cli":
      style = "cli"
    elif boot.lower() == "gui":
      style = "gui"
    else:
      exit()

    if os.path.exists("UserData.txt"):
      new_user = False
      if os.path.exists("Passwords.txt"):
         pass
      else:
         with open("Passwords.txt", "w") as c:
            c.close()
    else:
      new_user = True
      with open("UserData.txt", "w") as c:
        c.close()
      if os.path.exists("Passwords.txt"):
         os.remove("Passwords.txt")
         with open("Passwords.txt", "w") as c:
            c.close()
      else:
        with open("Passwords.txt", "w") as c:
          c.close()
      login_creation_cli()
    login_cli()

if __name__=="__main__":
    boot()
