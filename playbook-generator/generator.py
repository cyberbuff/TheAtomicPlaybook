from attackcti import attack_client
from stix2 import TAXIICollectionSource, Filter, CompositeDataSource, FileSystemSource
from sys import platform
import yaml
from enum import Enum
import json
from functools import reduce
from models import AttackTactic, AttackTechnique, _atomics_folder_path, _home_path, JupyterCells
import os



class PlaybookGenerator:
    def __init__(self):
        self.attack_client = attack_client()
        # We use only Enterprise ATT&CK matrix.
        self.attack_client.COMPOSITE_DS = self.attack_client.TC_ENTERPRISE_SOURCE

    def generate_toc(self):
        #TODO: Generate TOC automatically
        pass

    def get_tactics(self):
        stix_tactics = self.attack_client.get_enterprise_tactics()
        stix_tactics.sort(key=lambda x:x["external_references"][0]["external_id"])
        #TODO: Swap Exfiltration and C2C
        markdown = []
        markdown.append("| ID      | Name | Description |")
        markdown.append("| :--------: | :---------: | :---------: |")
        for i in stix_tactics:
            tactic = AttackTactic(i,self.get_techniques_by_tactic(i["x_mitre_shortname"]))
            self.generate_notebook(file_name=f'{os.path.dirname(os.getcwd())}/playbook/tactics/{tactic.short_name}/{tactic.short_name}', cells=tactic.__repr__())
            markdown.append(f'| {tactic.id} | {tactic.name} | {tactic.description} |')
        cells = [JupyterCells.quick_initialize_markdown(markdown).__repr__()]
        self.generate_notebook(file_name=f'{os.path.dirname(os.getcwd())}/playbook/tactics/tactics', cells=cells)
        

    def get_techniques_by_tactic(self, tactic):
        folder_path = f'{os.path.dirname(os.getcwd())}/playbook/tactics/{tactic}'
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        techniques = self.attack_client.get_techniques_by_tactic(tactic)
        json_techniques = []
        for stix in techniques:
            technique_id = stix["external_references"][0]["external_id"]
            file_path = f'{_atomics_folder_path}/{technique_id}/{technique_id}.yaml'
            if(os.path.exists(file_path)):
                with open(file_path,"r") as f:
                    atomic = yaml.load(f.read(), Loader=yaml.SafeLoader)
                    playbook_technique = AttackTechnique(stix, atomic)
            else:
                playbook_technique = AttackTechnique(stix)
            self.generate_notebook(file_name=f'{folder_path}/{technique_id}', cells=playbook_technique.__repr__())
            json_techniques.append({
                "id" : technique_id,
                "name" : stix.name,
                "description" : stix.description
            })
        return json_techniques

    def generate_notebook(self, file_name, cells):    
        file = f'{file_name}.ipynb'
        # if os.path.exists(file):
        #     pass
        with open(file,"w") as f:
            final_json = {
                "cells" : cells,
                "metadata": {
                    "kernelspec": {
                        "display_name": ".NET (PowerShell)",
                        "language": "PowerShell",
                        "name": ".net-powershell"
                    },
                    "language_info": {
                        "file_extension": ".ps1",
                        "mimetype": "text/x-powershell",
                        "name": "PowerShell",
                        "pygments_lexer": "powershell",
                        "version": "7.0"
                    }
                },
                "nbformat": 4,
                "nbformat_minor": 4
            }
            f.write(json.dumps(final_json, sort_keys=True, indent=1))
    
    def start(self):
        self.get_tactics()
# def test():
#     techniques = lift.get_techniques_by_tactic("discovery")
#     # techniques = [techniques[0]]
#     for stix in techniques:
#         playbook_technique = {}
#         technique_id = stix["external_references"][0]["external_id"]
#         file_path = f'{_atomics_folder_path}/{technique_id}/{technique_id}.yaml'
#         if(os.path.exists(file_path)):
#             with open(file_path,"r") as f:
#                 atomic = yaml.load(f.read(), Loader=yaml.SafeLoader)
#                 playbook_technique = AttackTechnique(stix, atomic)
#         else:
#             playbook_technique = AttackTechnique(stix)
#         # with open(f'{technique_id}.ipynb',"w") as f:
#         #     final_json = {
#         #         "cells" : playbook_technique.__repr__(),
#         #         "metadata": {
#         #             "kernelspec": {
#         #                 "display_name": ".NET (PowerShell)",
#         #                 "language": "PowerShell",
#         #                 "name": ".net-powershell"
#         #             },
#         #             "language_info": {
#         #                 "file_extension": ".ps1",
#         #                 "mimetype": "text/x-powershell",
#         #                 "name": "PowerShell",
#         #                 "pygments_lexer": "powershell",
#         #                 "version": "7.0"
#         #             }
#         #         },
#         #         "nbformat": 4,
#         #         "nbformat_minor": 4
#         #     }
#         #     f.write(json.dumps(final_json, sort_keys=True, indent=1))

if __name__ == "__main__":
    gen = PlaybookGenerator()
    gen.start()

