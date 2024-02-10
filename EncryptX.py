#----------------------------------Modules----------------------------------#

import base64
import ctypes
import gc
import os
import random
import sys
import time
import json
import threading
import tkinter
from tkinter import ttk

import customtkinter
import keyboard
import pyautogui
import pyperclip
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from CTkMessagebox import CTkMessagebox

#----------------------------------Constants----------------------------------#

version = "v1.1.7a"
SW_HIDE = 0
SW_SHOW = 5
counting_thread = None

#----------------------------------Functions----------------------------------#

class CryptoHandler():
   def generate_key(self, password):

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

   def encryption(self, key, plaintext):
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

   def decryption (self, key, ciphertext_encoded):
      try:
         ciphertext = base64.b64decode(ciphertext_encoded)

         iv = ciphertext[:16]

         cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
         decryptor = cipher.decryptor()

         decrypted_padded = decryptor.update(ciphertext[16:]) + decryptor.finalize()

         unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
         decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

         return decrypted

      except Exception as e:
         print("Error Decrypting! " + str(e))

# Keybinds #

def lock_bind():
   try:
      del key
   except:
      pass

   gc.collect()
   os.execl(sys.executable, sys.executable, *sys.argv)

def exit_bind():
   gc.collect()
   os._exit(0)

# Password Related #

def get_data():
   ready_data = []

   if os.path.isfile("Passwords.encryptx") != True:
      with open("Passwords.encryptx", "w") as w:
         w.close()
      
   with open("Passwords.encryptx", "rb") as read:
      split_data = read.read().split(b"\n")
      read.close()

   for data in split_data:
         if data:
            url_or_program, user, password = data.split(b"04n$b3e0R5K*")
            url_or_program, user, password = base64.b64decode(url_or_program), base64.b64decode(user), base64.b64decode(password)
            url_or_program = crypto_handler.decryption(key, url_or_program).decode()
            user = crypto_handler.decryption(key, user).decode()
            password = crypto_handler.decryption(key, password).decode()
            rating = password_rating_check(password)
            ready_data.append([url_or_program, user, password, rating]) 

   for ind, x in enumerate(ready_data):
      x.insert(0, ind) 

   return ready_data

def add_password(url_or_program, user, password):
   password = bytes(password, "utf-8")
   user = bytes(user, "utf-8")
   url_or_program = bytes(url_or_program, "utf-8")
   encrypted_password = (crypto_handler.encryption(key, password)).encode("utf-8")
   encrypted_username = (crypto_handler.encryption(key, user)).encode("utf-8")
   encrypted_url_or_program = (crypto_handler.encryption(key, url_or_program)).encode("utf-8")

   with open("Passwords.encryptx", "ab") as p:
      p.write(base64.b64encode(encrypted_url_or_program) + b"04n$b3e0R5K*" + base64.b64encode(encrypted_username) + b"04n$b3e0R5K*" + base64.b64encode(encrypted_password) + b"\n")            
       
def remove_password(index):
   with open("Passwords.encryptX", "rb") as read:
      lines = read.readlines()
      read.close()
   with open("Passwords.encryptX", "wb") as write:
      for index_of_line, line in enumerate(lines):
         if index_of_line != int(index):
            write.write(line)

   refresh_treeview()
   refresh_stats()
      
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

def password_generator(length: int, special: bool):
   if special == "yes":
      characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%^&*()"
   else:
      characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
   generated_password = ""
   for i in range(length):
      generated_password += random.choice(characters)

   return generated_password

#----------------------------------Main GUI----------------------------------#

def save_data():
   with open("userData.json", "w") as s:
      json.dump(userdata, s, indent=4)

def refresh_stats():
   ready_data = get_data()
   global total_passwords_value
   total_passwords_value = len(ready_data)
   total_passwords_label.configure(text=("Passwords Saved ~> ", total_passwords_value))

def refresh_treeview():
   for item in tree.get_children():
      tree.delete(item)

   ready_data = get_data()
   for line in ready_data:
      modified_line = list(line)
      modified_line[3] = "••••••••"
      modified_line = tuple(modified_line)
      
      tree.insert("", "end", values=modified_line)

def add_password_gui(root, tree):
   add_password_window = customtkinter.CTkToplevel(root)
   add_password_window.geometry("400x200")
   add_password_window.title("Add Password")
   name_text_box = customtkinter.CTkEntry(add_password_window, placeholder_text="Name/URL")
   username_text_box = customtkinter.CTkEntry(add_password_window, placeholder_text="Username")
   password_text_box = customtkinter.CTkEntry(add_password_window, placeholder_text="Password", show="*")
   name_text_box.pack(padx=10, pady=10)
   username_text_box.pack(padx=10, pady=10)
   password_text_box.pack(padx=10, pady=10)

   def send_info(tree):
      name = name_text_box.get()
      username = username_text_box.get()
      password = password_text_box.get()

      add_password(name, username, password)
      refresh_treeview()
      refresh_stats()

      add_password_window.destroy()

   save_button = tkinter.Button(add_password_window, text="Add Password", command=lambda: send_info(tree))
   save_button.pack(pady=5)

def change_master_password_gui():
   change_password_gui = customtkinter.CTkToplevel(root)
   change_password_gui.geometry("400x200")
   change_password_gui.title("Change Master Password")
   original_password_box = customtkinter.CTkEntry(change_password_gui, placeholder_text="Original Password", show="*")
   new_password_box = customtkinter.CTkEntry(change_password_gui, placeholder_text="New Password", show="*")
   new_password_box2 = customtkinter.CTkEntry(change_password_gui, placeholder_text="Re-Type New Password", show="*")
   original_password_box.pack(padx=10, pady=10)
   new_password_box.pack(padx=10, pady=10)
   new_password_box2.pack(padx=10, pady=10)

   def change_master_password(org_pass, new_pass1, new_pass2):
      if new_pass1 == new_pass2:
         if login_check_function(org_pass):
            passwords = get_data()

            os.remove("Passwords.encryptx")

            login_create_function(new_pass1, new_pass2)

            for item in passwords:
               add_password(item[1], item[2], item[3])

            change_password_gui.destroy()

   change_button = tkinter.Button(change_password_gui, text="Change Master Password", command=lambda: change_master_password(original_password_box.get(), new_password_box.get(), new_password_box2.get()))
   change_button.pack(pady=5)

class CountThread(threading.Thread):
   def __init__(self):
      super(CountThread, self).__init__()
      self.counting = True

   def run(self):
      count = duration
      while self.counting and count > 0:
         count -= 1
         time.sleep(1)

      if count == 0:
         ctypes.windll.user32.OpenClipboard(0)
         ctypes.windll.user32.EmptyClipboard()
         ctypes.windll.user32.CloseClipboard()

def copy_user_or_pass(itemid, copy):
   global counting_thread
   ready_data = get_data()
   data = ready_data[int(itemid)]

   if copy == "user":
      user = data[2]
      pyperclip.copy(user)
   elif copy == "pass":
      password = data[3]
      pyperclip.copy(password)

   if duration != -1:
      if counting_thread is None or not counting_thread.is_alive():
         counting_thread = CountThread()
         counting_thread.start()
      else:
         counting_thread.counting = False
         counting_thread.join()
         counting_thread = CountThread()
         counting_thread.start()

def show_password(tree, item):
   ready_data = get_data()
   data = ready_data[int(item)]

   for item in tree.get_children():
      tree.delete(item)

   for line in ready_data:
      if line == data:
         tree.insert("", "end", values=line)
      else:
         modified_line = list(line)
         modified_line[3] = "••••••••"
         modified_line = tuple(modified_line)

         tree.insert("", "end", values=modified_line)

def autotype(items):
   msg = CTkMessagebox(title="Autotype", message=f"Auto Type In Previous Window?",
                        icon="question", option_1="No", option_2="Yes", width=300, height=100)
   response = msg.get()

   if response=="Yes":
      keyboard.press_and_release("alt+tab")

      time.sleep(1)

      if len(items) > 1:
         pyautogui.typewrite(items[0], interval=0.01)
         keyboard.press("tab")
         pyautogui.typewrite(items[1], interval=0.01)
      else:
         pyautogui.typewrite(items[0], interval=0.01)

def on_right_click(event):
   item = tree.identify_row(event.y)
   if item != "":
      item_id = tree.item(item, "values")[0]

   if item:
      menu = tkinter.Menu(root, tearoff=0)
      autotype_menu = tkinter.Menu(menu, tearoff=0)
      menu.add_command(label="Remove Item", command=lambda:remove_password(item_id))
      menu.add_command(label="Copy Username", command=lambda:copy_user_or_pass(item_id, copy="user"))
      menu.add_command(label="Copy Password", command=lambda:copy_user_or_pass(item_id, copy="pass"))
      menu.add_command(label="Show Password", command=lambda:show_password(tree, item_id))
      menu.add_command(label="Hide Password", command=lambda:refresh_treeview())

      autotype_menu.add_command(label="Username & Password", command=lambda: autotype([get_data()[int(item_id)][2], get_data()[int(item_id)][3]]))
      autotype_menu.add_command(label="Username", command=lambda: autotype([get_data()[int(item_id)][2]]))
      autotype_menu.add_command(label="Password", command=lambda: autotype([get_data()[int(item_id)][3]]))

      menu.add_cascade(label="Auto Type", menu=autotype_menu)
      menu.tk_popup(event.x_root, event.y_root)

def combobox_callback(choice):

   # Theme Stuff

   if choice == "Dark Mode":
      style = ttk.Style(root)
      style.theme_use("clam")
      style.configure("Treeview", background="#565656", fieldbackground="#060202", foreground="white")
      customtkinter.set_appearance_mode("dark")
      userdata["settings"]["theme"] = "Dark Mode"
   elif choice == "Light Mode":
      style = ttk.Style(root)
      style.theme_use("clam")
      style.configure("Treeview", background="#BFBFBF", fieldbackground="#F0F0F0", foreground="#333333")
      customtkinter.set_appearance_mode("light")
      userdata["settings"]["theme"] = "Light Mode"

   # Clipboard Clear Stuff
      
   global duration

   if choice == "Dont Clear":
      duration = -1
      userdata["settings"]["clear_password_duration"] = "-1"
   else:
      try:
         duration = int(choice)
         userdata["settings"]["clear_password_duration"] = choice
      except:
         pass

   save_data()

def encrypt(entered_key):
   generated_key = crypto_handler.generate_key(entered_key)
   path = tkinter.filedialog.askopenfilename()

   if len(path) == 0:
      return
   
   if path.endswith('.encryptx'):
      return
   
   with open(path, "rb") as f:
      lines = f.readlines()
      f.close

   with open(path, "wb") as f:
      f.write(b"")
      f.close

   with open(path, "ab") as f:
      for line in lines:
         encrypted_line = crypto_handler.encryption(generated_key, line)
         f.write(encrypted_line.encode() + b"\n")

   os.rename(path, (path + ".encryptx"))

def decrypt(entered_key):
   generated_key = crypto_handler.generate_key(entered_key)
   path = tkinter.filedialog.askopenfilename()

   if len(path) == 0:
      return
   
   if not path.endswith('.encryptx'):
      return
   
   with open(path, "rb") as f:
      lines = f.readlines()
      f.close

   with open(path, "wb") as f:
      f.write(b"")
      f.close

   with open(path, "ab") as f:
      fail = False
      for line in lines:
         try:
            decrypted_line = crypto_handler.decryption(generated_key, line)
            f.write(decrypted_line)
         except:
            f.write(line)
            fail = True

   if not fail:
      os.rename(path, path[:-len(".encryptx")])

def slider_event(value):
   global password_generated
   special = use_special.get()
   password_generated = password_generator(int(value), special)
   length_set.configure(text=f"Password Length: {int(value)}")
   password_generated_label.configure(text=f"Password: {password_generated}")
   
def checkbox_event():
   global length, password_generated
   length = slider.get()
   special = use_special.get()
   password_generated = password_generator(int(length), special)
   password_generated_label.configure(text=f"Password: {password_generated}")

def main_gui():
   global root, tree

   keyboard.add_hotkey('Ctrl+Alt+L', lock_bind)

   root = customtkinter.CTk()
   root.geometry("1400x800")
   root.title(f"EncryptX {version}")

   tabview = customtkinter.CTkTabview(root, width=1400, height=800)
   tabview.pack(pady=5,padx=5)
   tabview.add("Passwords")
   tabview.add("Crypto Tool")
   tabview.add("Password Generator") 
   tabview.add("Binds")
   tabview.add("Stats")
   tabview.add("Settings") 

   # Password Page   

   try: 
      ready_data = get_data()
   except:
      pass  

   if userdata["settings"]["theme"] == "Dark Mode":
      customtkinter.set_appearance_mode("dark")
      style = ttk.Style(root)
      style.theme_use("clam")
      style.configure("Treeview", background="#565656", fieldbackground="#060202", foreground="white")
   elif userdata["settings"]["theme"] == "Light Mode":
      customtkinter.set_appearance_mode("light")
      style = ttk.Style(root)
      style.theme_use("clam")
      style.configure("Treeview", background="#BFBFBF", fieldbackground="#F0F0F0", foreground="#333333")

   tree = ttk.Treeview(master=tabview.tab("Passwords"), columns=("ID", "Name/URL", "Username", "Password", "Password_Rating"), show="headings", style="Treeview")

   scrollbar = tkinter.ttk.Scrollbar(tree, orient=tkinter.VERTICAL, command=tree.yview)
   tree.configure(yscroll=scrollbar.set) 

   tree.heading("ID", text="ID")
   tree.heading("Name/URL", text="Name/URL")
   tree.heading("Username", text="Username")
   tree.heading("Password", text="Password")
   tree.heading("Password_Rating", text="Password Rating (1-5)")  

   refresh_treeview()

   tree.column("ID", anchor="center")
   tree.column("Name/URL", anchor="center")
   tree.column("Username", anchor="center")
   tree.column("Password", anchor="center")
   tree.column("Password_Rating", anchor="center") 

   tree.pack(fill="both", expand=True) 

   tree.bind("<Button-3>", on_right_click)

   add_password_button = customtkinter.CTkButton(master=tabview.tab("Passwords"), text="Add Password", font=("Cascadia Code", 12), command=lambda: add_password_gui(root, tree))
   add_password_button.pack(pady=(10,5), padx=5)

   refresh_button = customtkinter.CTkButton(master=tabview.tab("Passwords"), text="Refresh Passwords List", font=("Cascadia Code", 12), command=refresh_treeview)
   refresh_button.pack() 

   # Cryptography Tool

   crypto_tool_label = customtkinter.CTkLabel(master=tabview.tab("Crypto Tool"), text="Cryptography Tool", font=("Cascadia Code", 18))
   crypto_tool_label.pack(pady=(20,5), padx=5)

   key_entry_box = customtkinter.CTkEntry(master=tabview.tab("Crypto Tool"), placeholder_text="Key", font=("Cascadia Code", 16))
   key_entry_box.pack(pady=(20,5), padx=5)

   encrypt_button = customtkinter.CTkButton(master=tabview.tab("Crypto Tool"), text="Encrypt File", font=("Cascadia Code", 16), command=lambda: encrypt(key_entry_box.get()))
   encrypt_button.pack(pady=5, padx=5)

   decrypt_button = customtkinter.CTkButton(master=tabview.tab("Crypto Tool"), text="Decrypt File", font=("Cascadia Code", 16), command=lambda: decrypt(key_entry_box.get()))
   decrypt_button.pack(pady=5, padx=5)

   # Password Generator

   length = 1

   global password_generated_label
   password_generated_label = customtkinter.CTkLabel(master=tabview.tab("Password Generator"), text=f"Password: Select A Length", font=("Cascadia Code", 16))
   password_generated_label.pack(pady=(20,5), padx=5)

   global length_set
   length_set = customtkinter.CTkLabel(master=tabview.tab("Password Generator"), text=f"Password Length: {int(length)}", font=("Cascadia Code", 16))
   length_set.pack(pady=(20,5), padx=5)

   global slider
   slider = customtkinter.CTkSlider(master=tabview.tab("Password Generator"), from_=1, to=44, command=slider_event)
   slider.pack(pady=(10,5), padx=5)
   slider.configure(number_of_steps=49)
   slider.set(1)

   global use_special
   use_special = customtkinter.CTkCheckBox(master=tabview.tab("Password Generator"), text="Special Characters", onvalue="yes", offvalue="no", command=checkbox_event)
   use_special.pack(pady=(10,5), padx=5)

   copy_password_button = customtkinter.CTkButton(master=tabview.tab("Password Generator"), text="Copy Password", font=("Cascadia Code", 18), command=lambda: pyperclip.copy(password_generated))
   copy_password_button.pack(pady=(10,5), padx=5)

   # Binds

   title_binds = customtkinter.CTkLabel(master=tabview.tab("Binds"), text="EncryptX Binds", font=("Cascadia Code", 22))
   title_binds.pack(pady=15, padx=10)

   exit_bind_label = customtkinter.CTkLabel(master=tabview.tab("Binds"), text="Exit >> Ctrl+Alt+E", font=("Cascadia Code", 12))
   exit_bind_label.pack(pady=(10,5), padx=5)

   lock_bind_label = customtkinter.CTkLabel(master=tabview.tab("Binds"), text="Lock >> Ctrl+Alt+L", font=("Cascadia Code", 12))
   lock_bind_label.pack(pady=(10,5), padx=5)

   # Stats Page

   title_stats = customtkinter.CTkLabel(master=tabview.tab("Stats"), text="EncryptX Stats", font=("Cascadia Code", 22))
   title_stats.pack(pady=15, padx=10)

   global total_passwords_label
   total_passwords_value = len(ready_data)
   total_passwords_label = customtkinter.CTkLabel(master=tabview.tab("Stats"), text=("Passwords Saved ~> ", total_passwords_value), font=("Cascadia Code", 12))
   total_passwords_label.pack(pady=(10,5), padx=5)

   # Settings Page

   settings_title = customtkinter.CTkLabel(master=tabview.tab("Settings"), text="Settings", font=("Cascadia Code", 28))
   settings_title.pack(pady=(10,5), padx=5)

   appearance_title = customtkinter.CTkLabel(master=tabview.tab("Settings"), text="Appearance", font=("Cascadia Code", 20))
   appearance_title.pack(pady=(10,5), padx=5)

   theme_var = customtkinter.StringVar(value=userdata["settings"]["theme"])
   theme = customtkinter.CTkComboBox(master=tabview.tab("Settings"), values=["Dark Mode", "Light Mode"], font=("Cascadia Code", 16), command=combobox_callback, variable=theme_var)
   theme_var.set(userdata["settings"]["theme"])
   theme.pack(pady=(10,5), padx=5)

   security_title = customtkinter.CTkLabel(master=tabview.tab("Settings"), text="Security", font=("Cascadia Code", 20))
   security_title.pack(pady=(10,5), padx=5)

   change_password_button = customtkinter.CTkButton(master=tabview.tab("Settings"), text="Change Password", font=("Cascadia Code", 16), command=change_master_password_gui)
   change_password_button.pack(pady=(10,5), padx=5)

   duration_label = customtkinter.CTkLabel(master=tabview.tab("Settings"), text="Clear Password Duration", font=("Cascadia Code", 16))
   duration_label.pack(pady=(10,5), padx=5)

   global duration
   duration = int(userdata["settings"]["clear_password_duration"])

   duration_var = customtkinter.StringVar(value=userdata["settings"]["clear_password_duration"])
   duration_combobox = customtkinter.CTkComboBox(master=tabview.tab("Settings"), values=["Dont Clear", "10", "15", "20", "25", "30", "60"], font=("Cascadia Code", 16), command=combobox_callback, variable=duration_var)
   duration_var.set(userdata["settings"]["clear_password_duration"])
   duration_combobox.pack(pady=(10,5), padx=5)

   root.mainloop()  

#----------------------------------Login Functions----------------------------------#

def login_check_function(master_pass):
   global key

   key = crypto_handler.generate_key(master_pass)

   decrypted_password = crypto_handler.decryption(key, userdata["masterpass"]["password"])
   if decrypted_password != None:
      if decrypted_password.decode("utf-8") == master_pass:
         return True
      else:
         return False
             
def login_create_function(master_pass, second_entry):
   global key

   if master_pass != second_entry:
      return False

   key = crypto_handler.generate_key(master_pass)
   encoded_password = bytes(master_pass, "utf-8")
   encrypted_password = crypto_handler.encryption(key, encoded_password)

   userdata["masterpass"]["password"] = encrypted_password
   save_data()

   return True

def login_check(master_pass):
   if login_check_function(master_pass):
      login.destroy()
      main_gui()

   os._exit(0)

def login_create(master_pass, second_entry):
   if login_create_function(master_pass, second_entry):
      login.destroy()
      main_gui()

   os._exit(0)

def login_creation_gui():
   global login

   hwnd = ctypes.windll.kernel32.GetConsoleWindow()
   if hwnd:
      ctypes.windll.user32.ShowWindow(hwnd, SW_HIDE)

   login = customtkinter.CTk()
   login.geometry("375x250")
   login.resizable(width=0, height=0)
   login.title(f"EncryptX {version} ~ Account Creation")

   title = customtkinter.CTkLabel(master=login, text="EncryptX", font=("Cascadia Code", 32))
   title.pack(pady=20, padx=5)

   password_box = customtkinter.CTkEntry(master=login, placeholder_text="Password", font=("Cascadia Code", 14), show="*", width=250)
   second_password_box = customtkinter.CTkEntry(master=login, placeholder_text="Re-Enter Password", font=("Cascadia Code", 14), show="*", width=250)
   password_box.pack(pady=5, padx=5)
   second_password_box.pack(pady=5, padx=5)

   button = customtkinter.CTkButton(master=login, text="Create Account", font=("Cascadia Code", 14), command=lambda:login_create(password_box.get(), second_password_box.get()))
   button.pack(pady=20, padx=5)

   login.mainloop()

def login_gui():
   global login

   hwnd = ctypes.windll.kernel32.GetConsoleWindow()
   if hwnd:
      ctypes.windll.user32.ShowWindow(hwnd, SW_HIDE)

   login = customtkinter.CTk()
   login.geometry("375x200")
   login.resizable(width=0, height=0)
   login.title(f"EncryptX {version} ~ Account Login")

   title = customtkinter.CTkLabel(master=login, text="EncryptX", font=("Cascadia Code", 22))
   title.pack(pady=20, padx=5)

   password_box = customtkinter.CTkEntry(master=login, placeholder_text="Password", font=("Cascadia Code", 14), show="*", width=250)
   password_box.pack(pady=5, padx=5)

   button = customtkinter.CTkButton(master=login, text="Login", font=("Cascadia Code", 14), command=lambda:login_check(password_box.get()))
   button.pack(pady=20, padx=5)

   login.mainloop()

#----------------------------------Boot----------------------------------#

def boot():
   global crypto_handler, userdata

   crypto_handler = CryptoHandler()

   keyboard.add_hotkey('Ctrl+Alt+E', exit_bind)

   userdata = {
      "masterpass": {
         "password": ""
      },
      "settings": {
         "theme": "Dark Mode",
         "clear_password_duration": "15"
      }
   }

   if not os.path.exists("userData.json"):
      with open("userData.json", "w") as s:
         json.dump(userdata, s, indent=4)
   else:
      with open('userData.json', 'r') as s:
         userdata = json.load(s)

   if userdata["settings"]["theme"] == "Dark Mode":
      customtkinter.set_appearance_mode("dark")
   elif userdata["settings"]["theme"] == "Light Mode":
      customtkinter.set_appearance_mode("light")

   if os.path.exists("userData.json") and userdata["masterpass"]["password"] != "":
      new_user = False
   else:
      new_user = True

   if new_user == True:
      login_creation_gui()
   elif new_user == False:
      login_gui()

if __name__=="__main__":
   boot()