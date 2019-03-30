from typing import List

from pg_objects.graph import Graph


class Object:
    name: str
    present: bool

    def __init__(self, name: str = None, present: bool = True):
        self.name = name
        self.present = present

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.name})"

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        return isinstance(self, type(other)) and self.key == other.key

    def __repr__(self):
        return f"<{self.key}>"

    def add_to_graph(self, graph: Graph):
        """
        Populate the graph so as to fully represent this object and its state.
        """
        graph.new_vertex(self)


class ObjectLink(Object):
    def __init__(self, present: bool = True):
        self.present = present

    @property
    def key(self):
        raise NotImplementedError()


class Group(Object):
    pass


class User(Object):
    groups: List[str]

    def __init__(self, name, groups: List[str] = None, present: bool = True):
        super().__init__(name=name, present=present)
        self.groups = groups

    def add_to_graph(self, graph: Graph):
        graph.new_vertex(self)
        for group in self.groups:
            GroupUser(group=group, user=self.name, present=self.present).add_to_graph(graph)


class GroupUser(ObjectLink):
    group: str
    user: str

    def __init__(self, group: str, user: str, present: bool = True):
        super().__init__(present=present)
        self.group = group
        self.user = user

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.group}+{self.user})"

    def add_to_graph(self, graph: Graph):
        graph.new_vertex(self)
        graph.add_edge(self, Group(self.group))
        graph.add_edge(self, User(self.user))


class Database(Object):
    owner: str

    def __init__(self, name, owner: str = None, present: bool = True):
        super().__init__(name=name, present=present)
        self.owner = owner

    def add_to_graph(self, graph: Graph):
        graph.new_vertex(self)
        DatabaseOwner(database=self.name, owner=self.owner, present=self.present).add_to_graph(graph)


class DatabaseOwner(ObjectLink):
    database: str
    owner: str

    def __init__(self, database: str, owner: str, present: bool = True):
        super().__init__(present=present)
        self.database = database
        self.owner = owner

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.database}+{self.owner})"

    def add_to_graph(self, graph: Graph):
        graph.new_vertex(self)
        graph.add_edge(self, Database(self.database))
        if self.owner:
            graph.add_edge(self, resolve_owner(self.owner, graph))


class Schema(Object):
    database: str
    owner: str

    def __init__(self, database: str, name: str, owner: str = None, present: bool = True):
        super().__init__(name=name, present=present)
        self.database = database
        self.owner = owner

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.database}.{self.name})"

    def add_to_graph(self, graph: Graph):
        graph.new_vertex(self)
        graph.add_edge(self, Database(self.database))
        if self.owner:
            graph.add_edge(self, resolve_owner(self.owner, graph))


def resolve_owner(owner: str, graph: Graph):
    group = Group(owner)
    user = User(owner)
    if group in graph:
        return group
    elif user in graph:
        return user
    raise ValueError(
        f"Ambiguous owner {owner!r} - "
        f"declare it as Group or User before referencing it as owner of another object"
    )


class Setup:
    def __init__(self):
        self._objects = []

    def group(self, name, **kwargs) -> Group:
        g = Group(name, **kwargs)
        self._objects.append(g)
        return g

    def user(self, name, **kwargs) -> User:
        u = User(name, **kwargs)
        self._objects.append(u)
        return u

    def database(self, name, **kwargs) -> Database:
        d = Database(name, **kwargs)
        self._objects.append(d)
        return d

    def schema(self, name, *, database, **kwargs) -> Schema:
        s = Schema(name=name, database=database, **kwargs)
        self._objects.append(s)
        return s

    @property
    def objects(self):
        return self._objects

    def generate_graph(self) -> Graph:
        g = Graph()
        for obj in self._objects:
            obj.add_to_graph(g)
        return g
