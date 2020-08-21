from enum import Enum
from functools import reduce
import os

_home_path = os.path.expanduser("~")
_atomics_folder_path = os.path.join(_home_path, "AtomicRedTeam", "atomics")

class JupyterCells:
    class Type(Enum):
        CODE = "code"
        MARKDOWN = "markdown"
        OUTPUT = "raw"

    def __init__(self, type:Type, value):
        self.type = type
        self.val = value
        self.hash_table = {"metadata": {}}
        self.hash_table["cell_type"] = self.type.value
        if type == JupyterCells.Type.CODE:
            self.hash_table["execution_count"] = None
            self.hash_table["outputs"] = []
            self.hash_table["source"] = value
        elif type == JupyterCells.Type.MARKDOWN:
            self.hash_table["source"] = value

    @staticmethod
    def quick_initialize_markdown(value: [str]):
        return JupyterCells(type=JupyterCells.Type.MARKDOWN, value=["\n".join(value)])

    @staticmethod
    def quick_initialize_code(value: [str]):
        return JupyterCells(type=JupyterCells.Type.CODE, value=["\n".join(value)])

    def __repr__(self):
        return self.hash_table


class AttackTechnique:
    def __init__(self, stix_object, atomic_object=None):
        self.description = stix_object["description"]
        self.name = stix_object["name"]
        self.id = stix_object["external_references"][0]["external_id"]
        self.detection = stix_object["x_mitre_detection"]
        # self.permissions_required = stix_object["x_mitre_permissions_required"]
        self.platforms = stix_object["x_mitre_platforms"]
        # self.defense_bypassed = stix_object["x_mitre_defense_bypassed"]
        # self.data_sources = stix_object["x_mitre_data_sources"]
        self.external_references = [i for i in stix_object["external_references"] if i["source_name"] != "mitre-attack"]
        self.atomic_tests = []
        if(atomic_object):
            self.name = atomic_object["display_name"]
            for index, value_dict in enumerate(atomic_object["atomic_tests"]):
                value_dict["technique_id"] = self.id
                value_dict["test_number"] = index+1
                self.atomic_tests.append(AtomicTest(value_dict))
        
    def has_atomic_tests(self):
        return self.atomic_tests.count != 0

    def __repr__(self):
        cells = []
        cells.append(JupyterCells(type=JupyterCells.Type.MARKDOWN,value=[f'# {self.id} - {self.name}', "\n", self.description]))
        if self.atomic_tests:
            cells.append(JupyterCells(type=JupyterCells.Type.MARKDOWN, value=["## Atomic Tests"]))
            cells.append(JupyterCells.quick_initialize_code(value=[f'#Import the Module before running the tests.\nImport-Module {_atomics_folder_path}/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force']))
            cells += reduce(lambda x,y: x+y,[i.__repr__() for i in self.atomic_tests])
        else:
            cells.append(JupyterCells.quick_initialize_markdown(value=["## Atomic Tests:","Currently, no tests are available for this technique."]))
        if self.detection:
            cells.append(JupyterCells(type=JupyterCells.Type.MARKDOWN, value=["## Detection", "\n", self.detection]))
        return [i.__repr__() for i in cells if i != dict()]
                
class AtomicTest:
    class AtomicDependency:
        def __init__(self, dependency_dict, executor):
            self.dependency_executor_name = executor
            self.check_pre_req_command = get_value_or_404(dependency_dict,"prereq_command")
            self.get_pre_req_command = get_value_or_404(dependency_dict,"get_prereq_command")
            self.description = get_value_or_404(dependency_dict,"description")

        def __repr__(self):
            """ This is the only __repr__ function which returns markdown string and not a Jupyter Cell object. """
            markdown = []
            markdown.append("##### Description: {0}".format(self.description))
            markdown.append("##### Check Prereq Commands:")
            markdown.append("```{0}\n{1}\n```".format(self.dependency_executor_name,self.check_pre_req_command))
            markdown.append("##### Get Prereq Commands:")
            markdown.append("```{0}\n{1}\n```".format(self.dependency_executor_name,self.get_pre_req_command))
            return "\n".join(markdown)

    def __init__(self, atomic_test:dict):
        self.technique_id = atomic_test["technique_id"]
        self.test_number = atomic_test["test_number"]
        self.name = atomic_test["name"]
        self.executor = atomic_test["executor"]["name"]
        self.description = atomic_test["description"]
        self.platforms = atomic_test["supported_platforms"]
        if self.executor == "manual":
            self.steps = atomic_test["executor"]["steps"]
        else:
            self.command = atomic_test["executor"]["command"]
        self.cleanup_command = get_value_or_404(atomic_test["executor"], "cleanup")
        self.elevation_required = get_value_or_404(atomic_test["executor"], "elevation_required")
        self.dependency_executor_name = get_value_or_404(atomic_test,"dependency_executor_name")
        if get_value_or_404(atomic_test,"dependencies"):
            self.dependencies = [AtomicTest.AtomicDependency(i,self.dependency_executor_name) for i in atomic_test["dependencies"]]
        else:
            self.dependencies = None

        if get_value_or_404(atomic_test,"input_arguments"):
            input_args = atomic_test["input_arguments"]
            self.command = self.replace_command_with_input_args(self.command, input_args)
            self.cleanup_command = self.replace_command_with_input_args(self.cleanup_command, input_args)
            if(get_value_or_404(atomic_test, "dependencies")):
                for i in self.dependencies:
                    i.get_pre_req_command = self.replace_command_with_input_args(i.get_pre_req_command, input_args)
                    i.check_pre_req_command = self.replace_command_with_input_args(i.check_pre_req_command, input_args)
        
    def __repr__(self):
        """ Converts AtomicTest to [JupyterCell] object"""
        cells = []
        markdown = []
        markdown += ["### Atomic Test #{0} - {1}".format(self.test_number,self.name),self.description]
        if self.platforms:
            markdown.append("**Supported Platforms:** {0}".format(", ".join(self.platforms)))
        if self.elevation_required:
            markdown.append("Elevation Required (e.g. root or admin)")
        if self.executor == "manual":
            markdown.append("Run it with these steps!")
            markdown.append(self.steps)
            cells.append(JupyterCells.quick_initialize_markdown(value=markdown))
        else:
            if self.dependencies:
                markdown.append("#### Dependencies:  Run with `{0}`!".format(self.dependency_executor_name))
                markdown.append("\n".join(i.__repr__() for i in self.dependencies))
                cells.append(JupyterCells.quick_initialize_markdown(value=markdown))
                cells.append(JupyterCells.quick_initialize_code(value=[f'Invoke-AtomicTest {self.technique_id} -TestNumbers {self.test_number} -GetPreReqs']))
                markdown = []
            markdown.append("#### Attack Commands: Run with `{0}`".format(self.executor))
            markdown.append("```{0}\n{1}```".format(self.executor, self.command))
            cells.append(JupyterCells.quick_initialize_markdown(value=markdown))
            cells.append(JupyterCells.quick_initialize_code(value=[f'Invoke-AtomicTest {self.technique_id} -TestNumbers {self.test_number}']))
            if self.cleanup_command:
                cells.append(JupyterCells.quick_initialize_markdown(["#### Cleanup: ", self.cleanup_command]))
                cells.append(JupyterCells.quick_initialize_code(value=[f'Invoke-AtomicTest {self.technique_id} -TestNumbers {self.test_number} -Cleanup']))
        return cells

    def replace_command_with_input_args(self, command:str, input_arguments:dict):
        """ Replace the input arguments in the commands."""
        if command:
            for k,v in input_arguments.items():
                command = command.replace(f'#{{{k}}}',str(v["default"]))
            return command
        else:
            return None

def get_value_or_404(json:dict, key:str):
    """ If a key is present in a dict, it returns the value of key else None."""
    try:
        return json[key]
    except:
        # print(f'{key} not found')
        return None

class AttackTactic:
    def __init__(self, stix_object, techniques):
        self.id = stix_object["external_references"][0]["external_id"]
        self.name = stix_object["name"]
        self.description = stix_object["description"]
        self.short_name = stix_object["x_mitre_shortname"]
        self.techniques = techniques

    def __repr__(self):
        markdown = []
        markdown.append(f'# {self.name}')
        markdown.append(self.description)
        markdown.append(f'## Techniques')
        markdown.append("| ID      | Name | Description |")
        markdown.append("| :--------: | :---------: | :---------: |")
        for i in self.techniques:
            markdown.append(f'{i["id"]} | {i["name"]} | {i["description"]}')
        cells = []
        cells.append(JupyterCells.quick_initialize_markdown(markdown))
        cells.append(JupyterCells.quick_initialize_code(["Invoke-AtomicTest-By -Tactic {0}".format(self.short_name)]))
        return [i.__repr__() for i in cells if i != dict()]