
#----------------------------------Modules----------------------------------#

import os
import colorama
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hashlib
import time
import keyboard
from tabulate import tabulate
import pyperclip
import random
import customtkinter
import base64
import tkinter
import ctypes

#----------------------------------Constants----------------------------------#

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

#----------------------------------Functions----------------------------------#

def generate_key(master_password, salt):
    backend = default_backend()
    iterations = 100000

    master_password_bytes = master_password.encode()
    salt_bytes = salt.encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt_bytes,
        iterations=iterations,
        backend=backend
    )

    key = kdf.derive(master_password_bytes)

    return key.hex()


def encryption(key, plaintext):
    backend = default_backend()
    block_size = algorithms.AES.block_size

    padder = padding.PKCS7(block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext

def decryption(key, ciphertext):
    backend = default_backend()
    block_size = algorithms.AES.block_size

    cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def exit_bind():
   pid = os.getpid()
   os.system(f"taskkill /F /PID {pid}")

def get_passwords():
    global ready_data
    ready_data = []

    with open("Passwords.txt", "rb") as read:
        split_data = read.read().split(b"\n")
        read.close()

    for data in split_data:
        if data:
            url_or_program, user, password = data.split(b"04n$b3e0R5K*")
            url_or_program, user, password = base64.b64decode(url_or_program), base64.b64decode(user), base64.b64decode(password)
            url_or_program = decryption(key, url_or_program).decode()
            user = decryption(key, user).decode()
            password = decryption(key, password).decode()
            rating = password_rating_check(password)
            ready_data.append([url_or_program, user, password, rating])
            
    for ind, x in enumerate(ready_data):
        x.insert(0, ind) 


def add_password(url_or_program, user, password):
    encrypted_password = encryption(key, password)
    time.sleep(0.2)
    encrypted_username = encryption(key, user)
    time.sleep(0.2)
    encrypted_url_or_program = encryption(key, url_or_program)
    time.sleep(0.2)

    with open("Passwords.txt", "ab") as p:
        p.write(base64.b64encode(encrypted_url_or_program) + b"04n$b3e0R5K*" + base64.b64encode(encrypted_username) + b"04n$b3e0R5K*" + base64.b64encode(encrypted_password) + b"\n")            
       
def remove_password(index):
   with open("Passwords.txt", "rb") as read:
      lines = read.readlines()
      read.close()
   with open("Passwords.txt", "wb") as write:
      for index_of_line, line in enumerate(lines):
         if index_of_line != int(index):
            write.write(line)

def password_rating_check(password):
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
       score +=1

    if uppercase_characters_present == True:
       score +=1

    if special_characters_present == True:
       score +=1

    if numbers_present == True:
       score +=1

    if len(password) >= 8:
      score +=1

    return score

#----------------------------------Main CLI----------------------------------#

def main_cli():
    os.system("cls")
    os.system(f"title Bacon Manager {version} ~ Logged In As {username_} ")
    os.system("mode con:cols=144 lines=42")
    print(colorama.Fore.LIGHTCYAN_EX + MAIN_MENU + colorama.Fore.RESET)
    opt = input(colorama.Fore.LIGHTCYAN_EX + "  BaconManager/Console/.. " + colorama.Fore.RESET)

    if opt == "":
       print(colorama.Fore.RED + "  !Invlid Option!" + colorama.Fore.RESET)
       time.sleep(1)
       main_cli()

    elif opt == "1":
       get_passwords()
       table_to_print = tabulate(ready_data, headers=["Index", "Name", "Username", "Password", "Rating (1-5)"], tablefmt="double_grid")
    
       lenght = len(table_to_print.split("\n")[0])
    
       os.system(f"cls && mode con:cols={lenght} lines=9999")
       print(colorama.Fore.LIGHTCYAN_EX + table_to_print + colorama.Fore.RESET)
       input()
       main_cli()

    elif opt == "2":
       os.system("cls & mode con:cols=80 lines=16")
       print(colorama.Fore.RED + "\nYour name, username or password can not be longer than 50 characters.\n" + colorama.Fore.RESET)
       url_or_program = input(colorama.Fore.LIGHTCYAN_EX + "\nWebsite Or Program Name ~> " + colorama.Fore.RESET)
       user = input(colorama.Fore.LIGHTCYAN_EX + "Username ~> " + colorama.Fore.RESET)
       password = input(colorama.Fore.LIGHTCYAN_EX + "Password To Store ~> " + colorama.Fore.RESET)

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

#----------------------------------Main GUI----------------------------------#

def refresh_treeview(tree):
   for item in tree.get_children():
      tree.delete(item)

   get_passwords()
   for line in ready_data:
      tree.insert("", "end", values=(line)) 

def add_password_gui(root, tree):
   info_window = customtkinter.CTkToplevel(root)
   info_window.geometry("400x200")
   info_window.title("Add Password")
   name_text_box = customtkinter.CTkEntry(info_window, placeholder_text="Name/URL")
   username_text_box = customtkinter.CTkEntry(info_window, placeholder_text="Username")
   password_text_box = customtkinter.CTkEntry(info_window, placeholder_text="Password")
   name_text_box.pack(padx=10, pady=10)
   username_text_box.pack(padx=10, pady=10)
   password_text_box.pack(padx=10, pady=10)

   def send_info(tree):
       name = name_text_box.get()
       username = username_text_box.get()
       password = password_text_box.get()

       add_password(name, username, password)

       for item in tree.get_children():
         tree.delete(item)

       get_passwords()
       for line in ready_data:
         tree.insert("", "end", values=(line)) 

       info_window.destroy()

   save_button = tkinter.Button(info_window, text="Add Password", command=lambda: send_info(tree))
   save_button.pack(pady=5)

def main_gui():

   root = customtkinter.CTk()
   root.geometry("900x700")
   root.resizable(width=0, height=0)
   root.title(f"Bacon Manager {version} ~ Logged In As {username_}")

   tabview = customtkinter.CTkTabview(root, width=900, height=700)
   tabview.pack(pady=5,padx=5)
   tabview.add("Passwords")
   tabview.add("Stats")
   tabview.add("Settings") 

   # Password Page   

   try: 
      get_passwords()
   except:
      pass  

   tree = tkinter.ttk.Treeview(master=tabview.tab("Passwords"), columns=("ID", "Name/URL", "Username", "Password", "Password_Rating"), show="headings")

   scrollbar = tkinter.ttk.Scrollbar(tree, orient=tkinter.VERTICAL, command=tree.yview)
   tree.configure(yscroll=scrollbar.set) 

   tree.heading("ID", text="ID")
   tree.heading("Name/URL", text="Name/URL")
   tree.heading("Username", text="Username")
   tree.heading("Password", text="Password")
   tree.heading("Password_Rating", text="Password Rating (1-5)")  

   for line in ready_data:
    tree.insert("", "end", values=(line)) 

   tree.column("ID", anchor="center")
   tree.column("Name/URL", anchor="center")
   tree.column("Username", anchor="center")
   tree.column("Password", anchor="center")
   tree.column("Password_Rating", anchor="center") 

   tree.pack(fill="both", expand=True) 

   add_password_button = customtkinter.CTkButton(master=tabview.tab("Passwords"), text="Add Password", command=lambda: add_password_gui(root, tree))
   add_password_button.pack(pady=(10,5), padx=5)

   refresh_button = customtkinter.CTkButton(master=tabview.tab("Passwords"), text="Refresh Passwords List", command=lambda: refresh_treeview(tree))
   refresh_button.pack()

   root.mainloop()   

   # Stats Page

   # Settings Page

#----------------------------------Login Functions----------------------------------#

def login_check(master_pass, username):
   global username_, key
   username_ = username
   
   if len(master_pass) < 8 or len(username) < 8:
      if style == "cli":
         print(colorama.Fore.RED + "\n   !Invalid Login!" + colorama.Fore.RESET)
         time.sleep(2)
         login_cli()
      else:
         login.destroy()
         exit

   salt = "UKXcH*=/:PSOF(*8y3Sau8ZVq/b(p1OVLA2gY)R.gbf@gx--48"
   key = generate_key(master_pass, salt)
   encrypted_password = encryption(key, master_pass)

   hash_password = hashlib.md5(encrypted_password).hexdigest()
   with open("UserData.txt", "r") as r:
      userdata = r.read().split("\n")
      r.close()
   
   for user in userdata:
      if user.split("04n$b3e0R5K*")[0] == username and user.split("04n$b3e0R5K*")[1] == hash_password:
         if style == "cli":
            main_cli()
         else:
            login.destroy()
            main_gui()
      else:
         if style == "cli":
            print(colorama.Fore.RED + "\n   !Invalid Login!" + colorama.Fore.RESET)
            time.sleep(2)
            login_cli()
         login.destroy()
         exit()
             
def login_create(master_pass, second_entry, username):
   global username_, key
   username_ = username

   if len(username) < 8:
     if style == "cli":
        login_creation_cli()
     else:
        login.destroy()
        exit()
   if len(master_pass) < 8 or master_pass != second_entry:
     if style == "cli":
        login_creation_cli()
     else:
        login.destroy()
        exit()
   if len(master_pass) > 64 or len(username) > 64:
     if style == "cli":
        login_creation_cli()
     else:
        login.destroy()
        exit()


   salt = "UKXcH*=/:PSOF(*8y3Sau8ZVq/b(p1OVLA2gY)R.gbf@gx--48"
   key = generate_key(master_pass, salt)
   encrypted_password = encryption(key, master_pass)
   hash_password = hashlib.md5(encrypted_password).hexdigest()

   with open("UserData.txt", "w") as w:
      w.write(f"{username}04n$b3e0R5K*{hash_password}")
      w.close()

   if style == "cli":
      main_cli()
   else:
      login.destroy()
      main_gui()

def login_creation_gui():
   global login

   SW_HIDE = 0
   SW_SHOW = 5
   hwnd = ctypes.windll.kernel32.GetConsoleWindow()
   if hwnd:
       ctypes.windll.user32.ShowWindow(hwnd, SW_HIDE)

   login = customtkinter.CTk()
   login.geometry("400x300")
   login.resizable(width=0, height=0)
   login.title(f"Bacon Manager {version} ~ Account Creation")

   title = customtkinter.CTkLabel(master=login, text="Bacon Manager", font=("Cascadia Code", 32))
   title.pack(pady=20, padx=5)

   username_box = customtkinter.CTkEntry(master=login, placeholder_text="Username", font=("Cascadia Code", 12))
   password_box = customtkinter.CTkEntry(master=login, placeholder_text="Password", font=("Cascadia Code", 12))
   second_password_box = customtkinter.CTkEntry(master=login, placeholder_text="Re-Enter Password", font=("Cascadia Code", 12))
   username_box.pack(pady=20, padx=5)
   password_box.pack(pady=5, padx=5)
   second_password_box.pack(pady=5, padx=5)

   button = customtkinter.CTkButton(master=login, text="Create Account", command=lambda:login_create(password_box.get(), second_password_box.get(), username_box.get()))
   button.pack(pady=20, padx=5)

   login.mainloop()

def login_gui():
   global login

   SW_HIDE = 0
   SW_SHOW = 5
   hwnd = ctypes.windll.kernel32.GetConsoleWindow()
   if hwnd:
       ctypes.windll.user32.ShowWindow(hwnd, SW_HIDE)

   login = customtkinter.CTk()
   login.geometry("400x300")
   login.resizable(width=0, height=0)
   login.title(f"Bacon Manager {version} ~ Account Login")

   title = customtkinter.CTkLabel(master=login, text="Bacon Manager", font=("Cascadia Code", 22))
   title.pack(pady=20, padx=5)

   username_box = customtkinter.CTkEntry(master=login, placeholder_text="Username", font=("Cascadia Code", 12))
   password_box = customtkinter.CTkEntry(master=login, placeholder_text="Password", font=("Cascadia Code", 12))
   username_box.pack(pady=20, padx=5)
   password_box.pack(pady=5, padx=5)

   button = customtkinter.CTkButton(master=login, text="Login", command=lambda:login_check(password_box.get(), username_box.get()))
   button.pack(pady=20, padx=5)

   login.mainloop()

def login_creation_cli():
    os.system(f"cls & title Bacon Manager {version} ~ Account Creation")
    print(colorama.Fore.RED + "\nYour username & password must be minimum 8 characters long and cant be longer than 64 characters!\n" + colorama.Fore.RESET)
    username = input(colorama.Fore.LIGHTCYAN_EX + "Username ~> " + colorama.Fore.RESET)
    master_pass = input(colorama.Fore.LIGHTCYAN_EX + "Enter Your Master Password ~> " + colorama.Fore.RESET)
    second_entry = input(colorama.Fore.LIGHTCYAN_EX + "Re-Enter The Password ~> " + colorama.Fore.RESET) 

    login_create(master_pass, second_entry, username)

def login_cli():
    os.system(f"title Bacon Manager {version} ~ Account Login & mode con:cols=80 lines=16")
    os.system("cls")
    username = input(colorama.Fore.LIGHTCYAN_EX + "\nUsername ~> " + colorama.Fore.RESET)
    master_pass = input(colorama.Fore.LIGHTCYAN_EX + "Enter Your Master Password ~> " + colorama.Fore.RESET)

    login_check(master_pass, username)

#----------------------------------Boot----------------------------------#

def boot():
    global style, version
    version = "v1.0"

    keyboard.add_hotkey('Ctrl+E', exit_bind)

    os.system(f"title Bacon Manager {version} & mode con:cols=80 lines=16")
    boot = input(colorama.Fore.LIGHTCYAN_EX + "Would you like to use CLI or GUI? " + colorama.Fore.RESET)
    if boot.lower() == "cli":
      style = "cli"
    elif boot.lower() == "gui":
      style = "gui"
    else:
      exit()

    if os.path.exists("UserData.txt"):
      new_user = False
    else:
      new_user = True

    if new_user == True and style == "cli":
       login_creation_cli()
    elif new_user == True and style == "gui":
       login_creation_gui()
    elif new_user == False and style == "cli":
       login_cli()
    elif new_user == False and style == "gui":
       login_gui()
    else:
       exit()

if __name__=="__main__":
    boot()