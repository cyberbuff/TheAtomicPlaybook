import json
import os

import nbformat.v4 as nbf
import yaml
from attackcti import attack_client
from models import AggregatedAtomic, AttackTactic, folder_paths


def generate_notebook(file_name, cells):
    file = f'{file_name}.ipynb'
    metadata = {
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
    }
    nb = nbf.new_notebook(metadata=metadata)
    nb["cells"] = cells
    with open(file, "w+") as f:
        f.write(json.dumps(nb, sort_keys=True, indent=1))


class PlaybookGenerator:
    def __init__(self):
        self.attack_client = attack_client()
        # We use only Enterprise ATT&CK matrix.
        self.attack_client.COMPOSITE_DS = self.attack_client.TC_ENTERPRISE_SOURCE

    def generate_toc(self):
        # TODO: Generate TOC automatically
        pass

    def get_tactics(self):
        if not os.path.exists(f'{os.getcwd()}/playbook/tactics'):
            os.mkdir(f'{os.getcwd()}/playbook/tactics')

        stix_tactics = self.attack_client.get_enterprise_tactics()
        stix_tactics.sort(
            key=lambda x: x["external_references"][0]["external_id"])
        # TODO: Swap Exfiltration and C2C
        markdown = [
            "| ID      | Name | Description |",
            "| -------- | --------- | --------- |"
        ]
        stix_tactics = filter(lambda x: x["external_references"][0]["external_id"] not in ["TA0042", "TA0043"],
                              stix_tactics)
        for i in stix_tactics:
            techniques = self.get_techniques_by_tactic(i["x_mitre_shortname"])
            tactic = AttackTactic(stix=i, techniques=techniques)
            generate_notebook(
                file_name=f'{os.getcwd()}/playbook/tactics/{tactic.stix.short_name}',
                cells=tactic.__repr__())
            desc = tactic.stix.description.split("\n")[0]
            markdown.append(f'| {tactic.stix.id} | {tactic.stix.name} | {desc}|')
        cells = [nbf.new_markdown_cell("\n".join(markdown))]
        generate_notebook(
            file_name=f'{os.getcwd()}/playbook/tactics',
            cells=cells)

    def get_techniques_by_tactic(self, tactic):
        folder_path = f'{os.getcwd()}/playbook/tactics/{tactic}'
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        techniques = self.attack_client.get_techniques_by_tactic(tactic)
        json_techniques = []
        for stix in techniques:
            technique_id = stix["external_references"][0]["external_id"]
            file_path = f'{folder_paths.ATOMICS_FOLDER}/{technique_id}/{technique_id}.yaml'
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    atomic = yaml.load(f.read(), Loader=yaml.SafeLoader)
                    playbook_technique = AggregatedAtomic(stix=stix, atomic=atomic)
            else:
                playbook_technique = AggregatedAtomic(stix=stix)
            generate_notebook(
                file_name=f'{folder_path}/{technique_id}',
                cells=playbook_technique.__repr__())
            json_techniques.append(playbook_technique)
        return json_techniques

    def start(self):
        self.get_tactics()


if __name__ == "__main__":
    gen = PlaybookGenerator()
    gen.start()
