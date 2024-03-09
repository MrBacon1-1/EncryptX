#----------------------------------Modules----------------------------------#

import ctypes
import gc
import os
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
from CTkMessagebox import CTkMessagebox
from Functions.CryptoHandler import CryptoHandler
from Functions.PasswordManager import PasswordManager
from Functions.VersionChecker import VersionChecker
from Functions.LoginManager import LoginManager
from Functions.Utilities import Utilities

crypto_handler = CryptoHandler()
password_manager = PasswordManager()
version_checker = VersionChecker()
login_manager = LoginManager()
utils = Utilities()

#----------------------------------Constants----------------------------------#

version = "1.2.3a"
SW_HIDE = 0
SW_SHOW = 5
counting_thread = None

#----------------------------------Keybinds----------------------------------#

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

#----------------------------------Functions----------------------------------#

def refresh_stats():
   data = password_manager.get_data(vault, key)
   global total_passwords_value
   total_passwords_value = len(data)
   total_passwords_label.configure(text=("Passwords Saved ~> ", total_passwords_value))

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

      password_manager.add_password(vault, name, username, password, key)
      password_manager.refresh_treeview(vault, tree, key)
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
         if login_manager.vault_login(vault, org_pass) != "":
            data = password_manager.get_data(vault, key)

            os.remove(f"{vault}.encryptx")

            new_key = login_manager.create_vault(vault, new_pass1, new_pass2)

            for item in data:
               password_manager.add_password(vault, item[1], item[2], item[3], new_key)

            change_password_gui.destroy()

            gc.collect()
            os.execl(sys.executable, sys.executable, *sys.argv)
         else:
            CTkMessagebox(title="Error!", message="An error occured while changing password!", icon="cancel")
      else:
         CTkMessagebox(title="Error!", message="An error occured while changing password!", icon="cancel")

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
   data = password_manager.get_data(vault, key)
   data = data[int(itemid)]

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
   data_ = password_manager.get_data(vault, key)
   data = data_[int(item)]

   for item in tree.get_children():
      tree.delete(item)

   for line in data_:
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
      menu.add_command(label="Remove Item", command=lambda:password_manager.remove_password(vault, tree, item_id, key))
      menu.add_command(label="Copy Username", command=lambda:copy_user_or_pass(item_id, copy="user"))
      menu.add_command(label="Copy Password", command=lambda:copy_user_or_pass(item_id, copy="pass"))
      menu.add_command(label="Show Password", command=lambda:show_password(tree, item_id))
      menu.add_command(label="Hide Password", command=lambda:password_manager.refresh_treeview(vault, tree, key))

      autotype_menu.add_command(label="Username & Password", command=lambda: autotype([password_manager.get_data(vault, key)[int(item_id)][2], password_manager.get_data(vault, key)[int(item_id)][3]]))
      autotype_menu.add_command(label="Username", command=lambda: autotype([password_manager.get_data(vault, key)[int(item_id)][2]]))
      autotype_menu.add_command(label="Password", command=lambda: autotype([password_manager.get_data(vault, key)[int(item_id)][3]]))

      menu.add_cascade(label="Auto Type", menu=autotype_menu)
      menu.tk_popup(event.x_root, event.y_root)

def combobox_callback(choice):

   # Theme Stuff

   if choice == "Dark Mode":
      style = ttk.Style(root)
      style.theme_use("clam")
      style.configure("Treeview", background="#565656", fieldbackground="#060202", foreground="white")
      customtkinter.set_appearance_mode("dark")
      settings["settings"]["theme"] = "Dark Mode"
   elif choice == "Light Mode":
      style = ttk.Style(root)
      style.theme_use("clam")
      style.configure("Treeview", background="#BFBFBF", fieldbackground="#F0F0F0", foreground="#333333")
      customtkinter.set_appearance_mode("light")
      settings["settings"]["theme"] = "Light Mode"

   # Clipboard Clear Stuff
      
   global duration

   if choice == "Dont Clear":
      duration = -1
      settings["settings"]["clear_password_duration"] = "-1"
   else:
      try:
         duration = int(choice)
         settings["settings"]["clear_password_duration"] = choice
      except:
         pass

   utils.save_json(settings)

def slider_event(value):
   global password_generated
   special = use_special.get()
   password_generated = password_manager.password_generator(int(value), special)
   length_set.configure(text=f"Password Length: {int(value)}")
   password_generated_label.configure(text=f"Password: {password_generated}")
   
def checkbox_event():
   global length, password_generated
   length = slider.get()
   special = use_special.get()
   password_generated = password_manager.password_generator(int(length), special)
   password_generated_label.configure(text=f"Password: {password_generated}")

#----------------------------------Main GUI----------------------------------#

def main_gui():
   global root, tree

   keyboard.add_hotkey('Ctrl+Alt+L', lock_bind)

   result = version_checker.compare_versions(version)

   root = customtkinter.CTk()
   root.geometry("1400x800")
   root.title(f"EncryptX | {vault} | v{version} {result}")

   tabview = customtkinter.CTkTabview(root, width=1400, height=800)
   tabview.pack(pady=5,padx=5)
   tabview.add("Passwords")
   tabview.add("Crypto Tool")
   tabview.add("Password Generator") 
   tabview.add("Binds")
   tabview.add("Stats")
   tabview.add("Settings") 

   # Password Page   

   data = password_manager.get_data(vault, key) 

   if settings["settings"]["theme"] == "Dark Mode":
      customtkinter.set_appearance_mode("dark")
      style = ttk.Style(root)
      style.theme_use("clam")
      style.configure("Treeview", background="#565656", fieldbackground="#060202", foreground="white")
   elif settings["settings"]["theme"] == "Light Mode":
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

   password_manager.refresh_treeview(vault, tree, key)

   tree.column("ID", anchor="center")
   tree.column("Name/URL", anchor="center")
   tree.column("Username", anchor="center")
   tree.column("Password", anchor="center")
   tree.column("Password_Rating", anchor="center") 

   tree.pack(fill="both", expand=True) 

   tree.bind("<Button-3>", on_right_click)

   add_password_button = customtkinter.CTkButton(master=tabview.tab("Passwords"), text="Add Password", font=("Cascadia Code", 12), command=lambda: add_password_gui(root, tree))
   add_password_button.pack(pady=(10,5), padx=5)

   refresh_button = customtkinter.CTkButton(master=tabview.tab("Passwords"), text="Refresh Passwords List", font=("Cascadia Code", 12), command=lambda: password_manager.refresh_treeview(vault, tree, key))
   refresh_button.pack() 

   # Cryptography Tool

   crypto_tool_label = customtkinter.CTkLabel(master=tabview.tab("Crypto Tool"), text="Cryptography Tool", font=("Cascadia Code", 18))
   crypto_tool_label.pack(pady=(20,5), padx=5)

   key_entry_box = customtkinter.CTkEntry(master=tabview.tab("Crypto Tool"), placeholder_text="Key", font=("Cascadia Code", 16))
   key_entry_box.pack(pady=(20,5), padx=5)

   encrypt_button = customtkinter.CTkButton(master=tabview.tab("Crypto Tool"), text="Encrypt File", font=("Cascadia Code", 16), command=lambda: crypto_handler.encrypt_file(key_entry_box.get()))
   encrypt_button.pack(pady=5, padx=5)

   decrypt_button = customtkinter.CTkButton(master=tabview.tab("Crypto Tool"), text="Decrypt File", font=("Cascadia Code", 16), command=lambda: crypto_handler.decrypt_file(key_entry_box.get()))
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
   slider = customtkinter.CTkSlider(master=tabview.tab("Password Generator"), from_=1, to=100, command=slider_event)
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
   total_passwords_value = len(data)
   total_passwords_label = customtkinter.CTkLabel(master=tabview.tab("Stats"), text=("Passwords Saved ~> ", total_passwords_value), font=("Cascadia Code", 12))
   total_passwords_label.pack(pady=(10,5), padx=5)

   # Settings Page

   settings_title = customtkinter.CTkLabel(master=tabview.tab("Settings"), text="Settings", font=("Cascadia Code", 28))
   settings_title.pack(pady=(10,5), padx=5)

   appearance_title = customtkinter.CTkLabel(master=tabview.tab("Settings"), text="Appearance", font=("Cascadia Code", 20))
   appearance_title.pack(pady=(10,5), padx=5)

   theme_var = customtkinter.StringVar(value=settings["settings"]["theme"])
   theme = customtkinter.CTkComboBox(master=tabview.tab("Settings"), values=["Dark Mode", "Light Mode"], font=("Cascadia Code", 16), command=combobox_callback, variable=theme_var)
   theme_var.set(settings["settings"]["theme"])
   theme.pack(pady=(10,5), padx=5)

   security_title = customtkinter.CTkLabel(master=tabview.tab("Settings"), text="Security", font=("Cascadia Code", 20))
   security_title.pack(pady=(10,5), padx=5)

   change_password_button = customtkinter.CTkButton(master=tabview.tab("Settings"), text="Change Password", font=("Cascadia Code", 16), command=change_master_password_gui)
   change_password_button.pack(pady=(10,5), padx=5)

   duration_label = customtkinter.CTkLabel(master=tabview.tab("Settings"), text="Clear Password Duration", font=("Cascadia Code", 16))
   duration_label.pack(pady=(10,5), padx=5)

   global duration
   duration = int(settings["settings"]["clear_password_duration"])

   duration_var = customtkinter.StringVar(value=settings["settings"]["clear_password_duration"])
   duration_combobox = customtkinter.CTkComboBox(master=tabview.tab("Settings"), values=["Dont Clear", "10", "15", "20", "25", "30", "60"], font=("Cascadia Code", 16), command=combobox_callback, variable=duration_var)
   duration_var.set(settings["settings"]["clear_password_duration"])
   duration_combobox.pack(pady=(10,5), padx=5)

   root.mainloop()  

#----------------------------------Login Functions----------------------------------#

def handle_login(password_box, login_gui):
   global key

   vault_path = tkinter.filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.encryptx")])
   if vault_path:
      vault_name = vault_path.split("/")[-1]
      vault_name = vault_name.split(".")[0]
   else:
      CTkMessagebox(title="Error!", message="Invalid Vault!", icon="cancel")

   try:
      result = login_manager.vault_login(vault_name, password_box)
   except:
      pass

   if result != "":
      global key, vault
      key = result
      vault = vault_name

      login_gui.destroy()
      main_gui()
   else:
      CTkMessagebox(title="Error!", message="Incorrect Password!", icon="cancel")

def vault_create(vault_name, password1, password2, login_gui):
   result = login_manager.create_vault(vault_name, password1, password2)

   if result != "":
      global key, vault
      key = result
      vault = vault_name

      login_gui.destroy()
      main_gui()
   else:
      CTkMessagebox(title="Error!", message="Incorrect Password Or Invalid Vault!", icon="cancel")

def create_vault_gui(initial):
   initial.destroy()

   login = customtkinter.CTk()
   login.geometry("375x300")
   login.resizable(width=0, height=0)
   login.title(f"EncryptX {version} ~ Create Vault")

   title = customtkinter.CTkLabel(master=login, text="EncryptX", font=("Cascadia Code", 32))
   title.pack(pady=20, padx=5)

   vault_name = customtkinter.CTkEntry(master=login, placeholder_text="Vault Name", font=("Cascadia Code", 14), width=250)
   vault_name.pack(pady=5, padx=5)

   password_box = customtkinter.CTkEntry(master=login, placeholder_text="Password", font=("Cascadia Code", 14), show="*", width=250)
   password_box.pack(pady=5, padx=5)

   second_password_box = customtkinter.CTkEntry(master=login, placeholder_text="Re-Enter Password", font=("Cascadia Code", 14), show="*", width=250)
   second_password_box.pack(pady=5, padx=5)

   button = customtkinter.CTkButton(master=login, text="Create Vault", font=("Cascadia Code", 14), command=lambda: vault_create(vault_name.get(), password_box.get(), second_password_box.get(), login))
   button.pack(pady=20, padx=5)

   login.mainloop()

def login_gui(initial):
   initial.destroy()

   login = customtkinter.CTk()
   login.geometry("375x200")
   login.resizable(width=0, height=0)
   login.title(f"EncryptX {version} ~ Open Vault")

   title = customtkinter.CTkLabel(master=login, text="EncryptX", font=("Cascadia Code", 22))
   title.pack(pady=20, padx=5)

   password_box = customtkinter.CTkEntry(master=login, placeholder_text="Password", font=("Cascadia Code", 14), show="*", width=250)
   password_box.pack(pady=5, padx=5)

   button = customtkinter.CTkButton(master=login, text="Select Vault", font=("Cascadia Code", 14), command=lambda: handle_login(password_box.get(), login))
   button.pack(pady=20, padx=5)

   login.mainloop()

def initial_menu():
   hwnd = ctypes.windll.kernel32.GetConsoleWindow()
   if hwnd:
      ctypes.windll.user32.ShowWindow(hwnd, SW_HIDE)

   initial = customtkinter.CTk()
   initial.geometry("375x200")
   initial.resizable(width=0, height=0)
   initial.title(f"EncryptX {version}")

   title = customtkinter.CTkLabel(master=initial, text="EncryptX", font=("Cascadia Code", 22))
   title.pack(pady=20, padx=5)

   button = customtkinter.CTkButton(master=initial, text="Open Vault", font=("Cascadia Code", 14), command=lambda: login_gui(initial))
   button.pack(pady=(20,5), padx=5)

   button = customtkinter.CTkButton(master=initial, text="Create Vault", font=("Cascadia Code", 14), command=lambda: create_vault_gui(initial))
   button.pack(pady=5, padx=5)

   initial.mainloop()

#----------------------------------Boot----------------------------------#

def boot():
   keyboard.add_hotkey('Ctrl+Alt+E', exit_bind)

   global settings
   settings = {
      "settings": {
         "theme": "Dark Mode",
         "clear_password_duration": "15"
      },
   }

   if not os.path.exists("Settings.json"):
      with open("Settings.json", "w") as s:
         json.dump(settings, s, indent=4)
   else:
      with open('Settings.json', 'r') as s:
         settings = json.load(s)

   if settings["settings"]["theme"] == "Dark Mode":
      customtkinter.set_appearance_mode("dark")
   elif settings["settings"]["theme"] == "Light Mode":
      customtkinter.set_appearance_mode("light")

   initial_menu()

if __name__=="__main__":
   boot()