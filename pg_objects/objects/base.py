import abc
from typing import Set, Generator, Optional, Union, Collection, Type, Hashable

from ..graph import Graph
from ..statements import Statement
from ..connection import Connection


class SetupAbc(abc.ABC):
    master_user: str
    master_database: str

    @abc.abstractmethod
    def register(self, obj: "Object"):
        raise NotImplementedError()

    @abc.abstractmethod
    def get(self, obj_or_key: Union["Object", Hashable]) -> Optional["Object"]:
        raise NotImplementedError()

    @abc.abstractmethod
    def __contains__(self, obj_or_key: Union["Object", Hashable]) -> bool:
        raise NotImplementedError()

    @abc.abstractmethod
    def resolve_role(self, rolname: str, present: bool = True):
        raise NotImplementedError()

    @abc.abstractmethod
    def get_connection(self, database: str = None) -> Connection:
        raise NotImplementedError()

    def get_current_state(self, obj: "Object") -> "ObjectState":
        raise NotImplementedError()


class ObjectState(str):
    # The object currently exists
    IS_PRESENT: "ObjectState"

    # The object does not currently exist
    IS_ABSENT: "ObjectState"

    # The object currently exists and supports changes and we have detected a change.
    IS_DIFFERENT: "ObjectState"

    # The object may exist or may be missing, we do not support detection of its state,
    # need to apply the state / issue create statements.
    IS_UNKNOWN: "ObjectState"

    @property
    def is_absent(self):
        return self == self.IS_ABSENT

    @property
    def is_present(self):
        return self == self.IS_PRESENT

    @property
    def is_different(self):
        return self == self.IS_DIFFERENT

    @property
    def is_unknown(self):
        return self == self.IS_UNKNOWN


ObjectState.IS_PRESENT = ObjectState("IS_PRESENT")
ObjectState.IS_ABSENT = ObjectState("IS_ABSENT")
ObjectState.IS_DIFFERENT = ObjectState("IS_DIFFERENT")
ObjectState.IS_UNKNOWN = ObjectState("IS_UNKNOWN")


class Object:
    name: str
    present: bool
    setup: SetupAbc
    dependencies: Set["Object"]

    def __init__(
        self,
        name: str = None,
        present: bool = True,
        setup: SetupAbc = None,
        dependencies: Set["Object"] = None,
    ):
        self.name = name
        self.present = present
        self.setup = setup
        self.dependencies = dependencies or set()

    @property
    def key(self) -> str:
        return f"{self.__class__.__name__}({self.name})"

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        return isinstance(self, type(other)) and self.key == other.key

    def __repr__(self):
        return f"<{self.key}>"

    def resolve_role(self, rolname: str, present: bool = True) -> "Role":
        from .role import Group
        if self.setup is None:
            return Group(rolname, present=present)
        return self.setup.resolve_role(rolname, present=present)

    def add_to_graph(self, graph: Graph):
        """
        Populate the graph so as to fully represent this object and its state.
        """
        graph.new_vertex(self)
        for dep in self.dependencies:
            graph.add_edge(self, dep)

    def stmts_to_create(self) -> Generator[Statement, None, None]:
        """
        Yield statements that create the object.

        Do not yield statements that ObjectLinks are responsible for.
        For example, database owner should not be set on database creation because
        it is DatabaseOwner object's responsibility.
        """
        if False:
            yield

    def stmts_to_update(self) -> Generator[Statement, None, None]:
        """
        Yield statements that update the object to the desired state.

        These statements are executed if current state is IS_DIFFERENT.
        Most objects should avoid having a mutable state as it is easier to just
        create and drop objects.

        By default, create statements are yielded.
        """
        yield from self.stmts_to_create()

    def stmts_to_drop(self) -> Generator[Statement, None, None]:
        """
        Yield statements that drop the object.

        See stmts_to_create().
        """
        if False:
            yield

    def stmts_to_maintain(self) -> Generator[Statement, None, None]:
        """
        Yields statements that should be executed on every run if the object is to be present.

        You should use these only when the statements don't belong to creation, and
        it's not easy to detect the current state and express this state as a separate object.
        """
        if False:
            yield


class ObjectLink(Object):
    def __init__(self, present: bool = True, setup: SetupAbc = None):
        self.present = present
        self.setup = setup
        self.dependencies = set()

    @property
    def key(self):
        raise NotImplementedError()


def parse_privileges(privileges: Optional[Union[str, Collection[str]]], obj_type: Type[Object]):
    if not privileges:
        return set()
    if isinstance(privileges, str):
        privileges = {privileges}
    else:
        privileges = set(privileges)

    parsed = []

    for p in privileges:
        p = p.upper()

        if p == "ALL":
            parsed.extend(obj_type.ALL)
            continue

        # Known aliases
        if p == "TEMP":
            p = "TEMPORARY"

        if p not in obj_type.ALL:
            raise ValueError(f"Unsupported privilege {p!r} for {obj_type}")

        parsed.append(p)

    return set(parsed)
