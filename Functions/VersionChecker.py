import requests
from bs4 import BeautifulSoup

class VersionChecker:
    def compare_versions(self, version: str):
            try:
                version = "EncryptX " + version

                releases_url = f"https://github.com/MrBacon1-1/EncryptX/releases"
                response = requests.get(releases_url)

                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, "html.parser")
                    latest_release_tag = soup.find("a", class_="Link--primary")  # Example class name, replace with the correct one

                    if latest_release_tag:
                        latest_tag_name = latest_release_tag.text.strip()
                        if version < latest_tag_name:
                            return "| Update Available"
                        if version > latest_tag_name:
                            return "| DEV"
                        else:
                            return ""
                else:
                    return f"[VersionChecker] Failed to retrieve latest tag information. Status code: {response.status_code}"

            except:
                pass