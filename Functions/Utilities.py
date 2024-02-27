import json

class Utilities():
    def save_json(self, userdata: str):
        with open("userData.json", "w") as s:
            json.dump(userdata, s, indent=4)