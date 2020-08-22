import requests
from .models import shield_element_from_dict


class Shield:
    def __init__(self):
        shield_data = requests.get(
            "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/master/_data/attack_mapping.json").json()
        self.shield_objects = shield_element_from_dict(shield_data)

    def get_shield_obj(self, attack_id: str):
        for x in self.shield_objects:
            if x.attack_id == attack_id:
                return x


shield = Shield()
