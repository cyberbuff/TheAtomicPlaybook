import json
import os
from pathlib import Path

import nbformat.v4 as nbf
import yaml
from mitreattack.stix20 import MitreAttackData
from models import AggregatedAtomic, AttackTactic, folder_paths


def generate_notebook(file_name, cells):
    file = f"{file_name}.ipynb"
    metadata = {
        "kernelspec": {
            "display_name": ".NET (PowerShell)",
            "language": "pwsh",
            "name": ".net-powershell",
        },
        "language_info": {
            "file_extension": ".ps1",
            "mimetype": "text/x-powershell",
            "name": "pwsh",
            "pygments_lexer": "powershell",
            "version": "7.0",
        },
    }
    nb = nbf.new_notebook(metadata=metadata)
    nb["cells"] = cells
    with open(file, "w+") as f:
        f.write(json.dumps(nb, sort_keys=True, indent=1))


class PlaybookGenerator:
    def __init__(self):
        self.attack_client = MitreAttackData(
            f"{Path(folder_paths.ATOMICS_FOLDER).parent.absolute()}/atomic_red_team/enterprise-attack.json"
        )

    def generate_toc(self):
        arr = [
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact",
        ]
        sections = []
        for j in arr:
            path = os.path.join(os.getcwd(), "playbook", "tactics", j)
            sections.append(
                {
                    "file": f"tactics/{j}",
                    "sections": [
                        {"file": f"tactics/{j}/{i}"} for i in sorted(os.listdir(path))
                    ],
                }
            )

        with open(os.path.join(os.getcwd(), "playbook", "_toc.yaml"), "w") as f:
            toc = {
                "format": "jb-article",
                "root": "intro",
                "sections": [{"file": "tactics", "sections": sections}],
            }
            f.write(yaml.dump(toc, indent=2, sort_keys=False))

    def get_tactics(self):
        if not os.path.exists(f"{os.getcwd()}/playbook/tactics"):
            os.mkdir(f"{os.getcwd()}/playbook/tactics")

        stix_tactics = self.attack_client.get_tactics()
        stix_tactics.sort(key=lambda x: x["external_references"][0]["external_id"])
        # TODO: Swap Exfiltration and C2C
        markdown = [
            "| ID      | Name | Description |",
            "| -------- | --------- | --------- |",
        ]
        stix_tactics = filter(
            lambda x: x["external_references"][0]["external_id"]
            not in ["TA0042", "TA0043"],
            stix_tactics,
        )
        for i in stix_tactics:
            techniques = self.get_techniques_by_tactic(i["x_mitre_shortname"])
            tactic = AttackTactic(stix=i, techniques=techniques)
            generate_notebook(
                file_name=f"{os.getcwd()}/playbook/tactics/{tactic.stix.short_name}",
                cells=tactic.__repr__(),
            )
            desc = tactic.stix.description.split("\n")[0]
            markdown.append(f"| {tactic.stix.id} | {tactic.stix.name} | {desc}|")
        cells = [nbf.new_markdown_cell("\n".join(markdown))]
        generate_notebook(file_name=f"{os.getcwd()}/playbook/tactics", cells=cells)

    def get_techniques_by_tactic(self, tactic):
        folder_path = f"{os.getcwd()}/playbook/tactics/{tactic}"
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        techniques = self.attack_client.get_techniques_by_tactic(
            tactic, domain="enterprise-attack", remove_revoked_deprecated=True
        )
        json_techniques = []
        for stix in techniques:
            technique_id = stix["external_references"][0]["external_id"]
            file_path = (
                f"{folder_paths.ATOMICS_FOLDER}/{technique_id}/{technique_id}.yaml"
            )
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    atomic = yaml.load(f.read(), Loader=yaml.SafeLoader)
                    playbook_technique = AggregatedAtomic(stix=stix, atomic=atomic)
            else:
                playbook_technique = AggregatedAtomic(stix=stix)
            generate_notebook(
                file_name=f"{folder_path}/{technique_id}",
                cells=playbook_technique.__repr__(),
            )
            json_techniques.append(playbook_technique)
        return json_techniques

    def start(self):
        self.get_tactics()
        self.generate_toc()


if __name__ == "__main__":
    gen = PlaybookGenerator()
    gen.start()
