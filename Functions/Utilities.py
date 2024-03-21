import os
import json
import ctypes

class Utilities():
    def save_json(self, settings: str):
        with open("Settings.json", "w") as s:
            json.dump(settings, s, indent=4)


    def console_visibility(self, value: bool):
        if value:
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 5)

        if not value:
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)


    def clear_clipboard(self):
        ctypes.windll.user32.OpenClipboard(0)
        ctypes.windll.user32.EmptyClipboard()
        ctypes.windll.user32.CloseClipboard()


    def check_vault_status(self, path: str):
        if os.path.exists(path):
            return True
        else:
            return False