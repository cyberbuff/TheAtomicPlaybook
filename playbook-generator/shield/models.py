from typing import Any, List, TypeVar, Type, Callable, cast

T = TypeVar("T")

def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def to_markdown(c: Type[T], x: Any) -> str:
    assert isinstance(x, c)
    return cast(Any, x).to_markdown()


class AttackTechnique:
    id: str
    name: str

    def __init__(self, id: str, name: str):
        self.id = id
        self.name = name

    @staticmethod
    def from_dict(obj: Any) -> 'AttackTechnique':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        name = from_str(obj.get("name"))
        return AttackTechnique(id, name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_str(self.id)
        result["name"] = from_str(self.name)
        return result

    def to_markdown(self) -> str:
        return f'### Att&ckTechnique \n {self.id} - {self.name}'


class ShieldBaseObject:
    id: str
    description: str

    def __init__(self, id: str, description: str):
        self.id = id
        self.description = description

    @staticmethod
    def from_dict(obj: Any) -> 'ShieldBaseObject':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        description = from_str(obj.get("description"))
        return ShieldBaseObject(id, description)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_str(self.id)
        result["description"] = from_str(self.description)
        return result

class Opportunity(ShieldBaseObject):
    @staticmethod
    def from_dict(obj: Any) -> 'Opportunity':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        description = from_str(obj.get("description"))
        return Opportunity(id, description)

    def to_markdown(self) -> str:
        return f'### Opportunity\n{self.description}'


class UseCase(ShieldBaseObject):
    @staticmethod
    def from_dict(obj: Any) -> 'UseCase':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        description = from_str(obj.get("description"))
        return UseCase(id, description)

    def to_markdown(self) -> str:
        return f'### Use Case\n{self.description}'


class Procedure(ShieldBaseObject):
    #TODO: Change static initializers for all base objects.
    @staticmethod
    def from_dict(obj: Any) -> 'Procedure':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        description = from_str(obj.get("description"))
        return Procedure(id, description)

    def to_markdown(self) -> str:
        # Since Procedure is an array, it will have a common title. 
        return self.description


class ShieldTechnique:
    id: str
    name: str
    description: str
    long_description: str

    def __init__(self, id: str, name: str, description: str, long_description: str):
        self.id = id
        self.name = name
        self.description = description
        self.long_description = long_description

    @staticmethod
    def from_dict(obj: Any) -> 'ShieldTechnique':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        name = from_str(obj.get("name"))
        description = from_str(obj.get("description"))
        long_description = from_str(obj.get("long_description"))
        return ShieldTechnique(id, name, description, long_description)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_str(self.id)
        result["name"] = from_str(self.name)
        result["description"] = from_str(self.description)
        result["long_description"] = from_str(self.long_description)
        return result

    def to_markdown(self) -> str:
        # Since Opportunity is an array, it will have a common title. 
        return f'## {self.name} \n {self.description} \n\n {self.long_description}'

class ShieldElement:
    attack_id: str
    attack_technique: AttackTechnique
    opportunity: Opportunity
    use_case: UseCase
    technique: ShieldTechnique
    procedures: List[Procedure]

    def __init__(self, attack_id: str, attack_technique: AttackTechnique, opportunity: Opportunity, use_case: UseCase, technique: ShieldTechnique, procedures: List[Procedure]):
        self.attack_id = attack_id
        self.attack_technique = attack_technique
        self.opportunity = opportunity
        self.use_case = use_case
        self.technique = technique
        self.procedures = procedures

    @staticmethod
    def from_dict(obj: Any) -> 'ShieldElement':
        assert isinstance(obj, dict)
        attack_id = from_str(obj.get("attack_id"))
        attack_technique = AttackTechnique.from_dict(obj.get("attack_technique"))
        opportunity = Opportunity.from_dict(obj.get("opportunity"))
        use_case = UseCase.from_dict(obj.get("use_case"))
        technique = ShieldTechnique.from_dict(obj.get("technique"))
        procedures = from_list(Procedure.from_dict, obj.get("procedures"))
        return ShieldElement(attack_id, attack_technique, opportunity, use_case, technique, procedures)

    def to_dict(self) -> dict:
        result: dict = {}
        result["attack_id"] = from_str(self.attack_id)
        result["attack_technique"] = to_class(AttackTechnique, self.attack_technique)
        result["opportunity"] = to_class(Opportunity, self.opportunity)
        result["use_case"] = to_class(UseCase, self.use_case)
        result["technique"] = to_class(ShieldTechnique, self.technique)
        result["procedures"] = from_list(lambda x: to_class(Procedure, x), self.procedures)
        return result

    def to_markdown(self) -> str:
        procedures_md = "### Procedures\n" + "\n".join([x.to_markdown() for x in self.procedures])
        return "\n".join(["# Shield Active Defense", self.technique.to_markdown(), 
            self.opportunity.to_markdown(),
            self.use_case.to_markdown(), procedures_md
        ])

def shield_element_from_dict(s: Any) -> List[ShieldElement]:
    return from_list(ShieldElement.from_dict, s)


def shield_element_to_dict(x: List[ShieldElement]) -> Any:
    return from_list(lambda x: to_class(ShieldElement, x), x)