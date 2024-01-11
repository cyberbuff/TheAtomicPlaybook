import os.path
from typing import Dict, List, Literal, Optional

import nbformat.v4 as nbf
from pydantic import BaseModel, BaseSettings, Field, ValidationError
from shield.api import shield


def replace_command_with_input_args(command: str, input_arguments: dict):
    """Replace the input arguments in the commands."""
    if command:
        for k, v in input_arguments.items():
            command = command.replace(f"#{{{k}}}", str(v["default"]))
        return command
    else:
        return None


class FolderPaths(BaseSettings):
    ATOMICS_FOLDER: str = Field(..., env="PathToAtomicsFolder")


try:
    folder_paths = FolderPaths()
except ValidationError:
    # local development
    folder_paths = FolderPaths(ATOMICS_FOLDER="~/Pro/atomic-red-team/atomics")
    folder_paths.ATOMICS_FOLDER = os.path.expanduser(folder_paths.ATOMICS_FOLDER)


class STIXObject(BaseModel):
    description: str
    name: str
    detection: Optional[str] = Field(alias="x_mitre_detection", default=None)
    platforms: List[str] = Field(..., alias="x_mitre_platforms")
    technique_id: str

    def __init__(self, **data):
        data["technique_id"] = data["external_references"][0]["external_id"]
        super().__init__(**data)


class AtomicDependency(BaseModel):
    prereq_command: Optional[str]
    get_prereq_command: Optional[str]
    description: Optional[str]


class AtomicExecutor(BaseModel):
    name: Literal["manual", "powershell", "pwsh", "sh", "command_prompt", "bash"]
    steps: Optional[str]
    command: Optional[str]
    cleanup: Optional[str] = Field(default=None, alias="cleanup_command")
    elevation_required: Optional[str]


class AtomicTest(BaseModel):
    technique_id: str
    test_number: int
    name: str
    description: str
    platforms: List[str] = Field(..., alias="supported_platforms")
    executor: AtomicExecutor
    dependencies: Optional[List[AtomicDependency]]
    dependency_executor_name: Optional[str]
    input_arguments: Optional[Dict]

    def __init__(self, **data):
        super().__init__(**data)
        if args := self.input_arguments:
            self.executor.command = replace_command_with_input_args(
                self.executor.command, args
            )
            self.executor.cleanup = replace_command_with_input_args(
                self.executor.cleanup, args
            )
            if deps := self.dependencies:
                for i in deps:
                    i.get_prereq_command = replace_command_with_input_args(
                        i.get_prereq_command, args
                    )
                    i.prereq_command = replace_command_with_input_args(
                        i.prereq_command, args
                    )

    def __repr__(self):
        cells = []
        markdown = []
        markdown += [
            f"### Atomic Test #{self.test_number} - {self.name}",
            self.description,
        ]
        if self.platforms:
            markdown.append(
                "**Supported Platforms:** {0}".format(", ".join(self.platforms))
            )
        if self.executor.elevation_required:
            markdown.append("\nElevation Required (e.g. root or admin)")
        if self.executor.name == "manual":
            markdown.append("Run it with these steps!")
            markdown.append(self.executor.steps)
            cells.append(nbf.new_markdown_cell(markdown))
        else:
            if self.dependencies:
                markdown.append(
                    f"#### Dependencies:  Run with `{self.dependency_executor_name or self.executor.name}`!"
                )
                for dep in self.dependencies:
                    executor_name = self.executor.name
                    if executor_name == "command_prompt":
                        executor_name = "cmd"
                    markdown += [
                        f"##### Description: {dep.description}",
                        "##### Check Prereq Commands:",
                        f"```{executor_name}\n{dep.prereq_command}\n```",
                        "##### Get Prereq Commands:",
                        f"```{executor_name}\n{dep.get_prereq_command}\n```",
                    ]
                cells.append(nbf.new_markdown_cell("\n".join(markdown)))
                cells.append(
                    nbf.new_code_cell(
                        f"Invoke-AtomicTest {self.technique_id} -TestNumbers {self.test_number} -GetPreReqs"
                    )
                )
                markdown = []
            markdown.append(f"#### Attack Commands: Run with `{self.executor.name}`\n")
            markdown.append(f"```{self.executor.name}\n{self.executor.command}```")
            cells.append(nbf.new_markdown_cell(markdown))
            cells.append(
                nbf.new_code_cell(
                    f"Invoke-AtomicTest {self.technique_id} -TestNumbers {self.test_number}"
                )
            )
            if cleanup := self.executor.cleanup:
                executor_name = self.executor.name
                if executor_name == "command_prompt":
                    executor_name = "cmd"
                cells.append(
                    nbf.new_markdown_cell(
                        f"#### Cleanup: \n```{executor_name}\n{cleanup}```"
                    )
                )
                cells.append(
                    nbf.new_code_cell(
                        f"Invoke-AtomicTest {self.technique_id} -TestNumbers {self.test_number} -Cleanup"
                    )
                )
        return cells


class AtomicTechnique(BaseModel):
    name: str = Field(..., alias="display_name")
    tests: List[AtomicTest] = Field(..., alias="atomic_tests")

    def __init__(self, **data):
        for test_number, i in enumerate(data["atomic_tests"]):
            i["technique_id"] = data["attack_technique"]
            i["test_number"] = test_number + 1
        super().__init__(**data)


class STIXTactic(BaseModel):
    name: str
    description: str
    short_name: str = Field(..., alias="x_mitre_shortname")
    id: str

    def __init__(self, **data):
        data["id"] = data["external_references"][0]["external_id"]
        super().__init__(**data)


class AggregatedAtomic(BaseModel):
    stix: STIXObject
    atomic: Optional[AtomicTechnique]

    def __repr__(self):
        cells = [
            nbf.new_markdown_cell(
                f"# {self.stix.technique_id} - {self.stix.name}\n{self.stix.description}"
            )
        ]
        if atomic := self.atomic:
            cells.append(nbf.new_markdown_cell("## Atomic Tests"))
            for i in atomic.tests:
                cells += i.__repr__()
        else:
            cells.append(
                nbf.new_markdown_cell(
                    "## Atomic Tests:\nCurrently, no tests are available for this technique."
                )
            )
        if detection := self.stix.detection:
            cells.append(nbf.new_markdown_cell(f"## Detection\n{detection}"))
        if shield_obj := shield.get_shield_obj(self.stix.technique_id):
            cells.append(nbf.new_markdown_cell(shield_obj.to_markdown()))
        return cells

    def __notebook__(self):
        pass


class AttackTactic(BaseModel):
    stix: STIXTactic
    techniques: List[AggregatedAtomic]

    def __repr__(self):
        markdown = [
            f"# {self.stix.name}",
            self.stix.description,
            "## Techniques",
            "| ID      | Name | Description |",
            "| :--------: | :---------: | :---------: |",
        ]
        for i in self.techniques:
            markdown.append(
                f"{i.stix.technique_id} | {i.stix.name} | {i.stix.description}"
            )
        cells = [
            nbf.new_markdown_cell("\n".join(markdown)),
            nbf.new_code_cell(
                f"#Invoke-AtomicTest-By can be downloaded from "
                f"https://github.com/cyberbuff/ART-Utils/\nInvoke-AtomicTest-By -Tactic {self.stix.short_name}"
            ),
        ]
        return cells
