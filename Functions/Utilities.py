import json

class Utilities():
    def save_json(self, settings: str):
        with open("Settings.json", "w") as s:
            json.dump(settings, s, indent=4)