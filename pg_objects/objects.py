import collections
import hashlib
import logging
from typing import List, Generator, Hashable, Dict, Tuple, Union, ClassVar, Optional, Set

from .connection import Connection
from .graph import Graph


log = logging.getLogger(__name__)


class Statement:
    query: str
    params: Tuple
    database: str

    # Special value used for Statement.database to mark the statement that
    # it needs to be executed on all managed databases.
    ALL_DATABASES: ClassVar[str] = "ALL_DATABASES"

    def __repr__(self):
        db = ""
        if self.database:
            db = f"{self.database}: "
        return f"<{db}{self.query!r}, {self.params}>"

    @property
    def is_on_all_databases(self):
        """
        Returns True if the statement needs to be executed on all managed databases.
        """
        return self.database == self.ALL_DATABASES


class TextStatement(Statement):
    def __init__(self, query: str, *params, **kwargs):
        """
        Pass database= when the statement should be executed while connected to a particular database.
        """
        self.query = query
        self.params = params or ()
        self.database = kwargs.pop("database", None)
        assert not kwargs  # "database" is the only supported keyword argument

    def __iter__(self):
        yield self.query
        yield self.params


class CreateStatement(Statement):
    def __init__(self, obj: Union["Database", "Role", "Schema"], *params, **kwargs):
        self.obj = obj
        self.params = params or ()
        self.database = kwargs.pop("database", None)

    @property
    def query(self) -> str:
        return f"CREATE {self.obj.__class__.__name__.upper()} {self.obj.name}"


class DropStatement(Statement):
    def __init__(self, obj: Union["Database", "Role", "Schema"], *params, **kwargs):
        self.obj = obj
        self.params = params or ()
        self.database = kwargs.pop("database", None)

    @property
    def query(self) -> str:
        return f"DROP {self.obj.__class__.__name__.upper()} {self.obj.name}"


class Object:
    name: str
    present: bool
    setup: "Setup"
    dependencies: Set["Object"]

    def __init__(
        self,
        name: str = None,
        present: bool = True,
        setup: "Setup" = None,
        dependencies: Set["Object"] = None,
    ):
        self.name = name
        self.present = present
        self.setup = setup
        self.dependencies = dependencies or set()

    @property
    def key(self) -> str:
        return f"{self.__class__.__name__}({self.name})"

    @property
    def type_key(self) -> Hashable:
        # Objects that are database-specific should include database name in their type key.
        return self.__class__

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
    def __init__(self, present: bool = True, setup: "Setup" = None):
        self.present = present
        self.setup = setup
        self.dependencies = set()

    @property
    def key(self):
        raise NotImplementedError()


class Role(Object):
    """
    Do not use directly, instead use Group or User.
    """

    def stmts_to_create(self):
        yield CreateStatement(self)

    def stmts_to_drop(self):
        # TODO Add "reassign_to" attribute which would be used in these cases
        yield TextStatement(
            query=f"REASSIGN OWNED BY {self.name} TO {self.setup.master_user}",
            database=Statement.ALL_DATABASES,
        )
        yield DropStatement(self)


class Group(Role):
    pass


class User(Role):
    groups: List[str]
    password: str

    def __init__(
        self,
        name, password: str = None, groups: List[str] = None,
        present: bool = True, setup: "Setup" = None,
    ):
        super().__init__(name=name, present=present, setup=setup)
        self.password = password
        self.groups = groups or []
        for group in self.groups:
            self.dependencies.add(Group(group))

    def add_to_graph(self, graph: Graph):
        super().add_to_graph(graph)
        for group in self.groups:
            GroupUser(
                group=group, user=self.name,
                present=self.present, setup=self.setup,
            ).add_to_graph(graph)

    def stmts_to_maintain(self) -> Generator[Statement, None, None]:
        yield TextStatement(f"""
            ALTER USER {self.name}
            WITH NOCREATEDB NOSUPERUSER
            {self.get_password_sql()}
        """)

    def get_password_sql(self):
        password_sql = "NOLOGIN"
        if self.password:
            if self.password.startswith("md5"):
                password_hash = self.password
            else:
                password_hash = "md5" + hashlib.md5(f"{self.password}{self.name}".encode()).hexdigest()
            password_sql = f"LOGIN PASSWORD '{password_hash}'"
        return password_sql


class GroupUser(ObjectLink):
    group: str
    user: str

    def __init__(self, group: str, user: str, present: bool = True, setup: "Setup" = None):
        super().__init__(present=present, setup=setup)
        self.group = group
        self.user = user
        self.dependencies.add(Group(self.group))
        self.dependencies.add(User(self.user))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.group}+{self.user})"

    def stmts_to_create(self):
        yield TextStatement(f"ALTER GROUP {self.group} ADD USER {self.user}")

    def stmts_to_drop(self):
        yield TextStatement(f"ALTER GROUP {self.group} DROP USER {self.user}")


class Database(Object):
    owner: str

    def __init__(self, name, owner: str = None, present: bool = True, setup: "Setup" = None):
        super().__init__(name=name, present=present, setup=setup)
        self.owner = owner
        if self.owner:
            self.dependencies.add(self.setup.resolve_owner(self.owner))

    def add_to_graph(self, graph: Graph):
        super().add_to_graph(graph)
        if self.owner:
            DatabaseOwner(
                database=self.name, owner=self.owner,
                present=self.present, setup=self.setup,
            ).add_to_graph(graph)

    def stmts_to_create(self):
        yield CreateStatement(self)

    def stmts_to_drop(self):
        yield DropStatement(self)

    def stmts_to_maintain(self):
        # We don't allow public access to managed databases
        yield TextStatement(f"""
            REVOKE ALL PRIVILEGES
            ON DATABASE {self.name}
            FROM GROUP PUBLIC
        """)


class DatabaseOwner(ObjectLink):
    database: str
    owner: str

    def __init__(self, database: str, owner: str, present: bool = True, setup: "Setup" = None):
        super().__init__(present=present, setup=setup)
        self.database = database
        self.owner = owner
        self.dependencies.add(Database(self.database))
        self.dependencies.add(setup.resolve_owner(self.owner))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.database}+{self.owner})"

    def stmts_to_create(self):
        yield TextStatement(f"ALTER DATABASE {self.database} OWNER TO {self.owner}")


class Schema(Object):
    database: str
    owner: str

    def __init__(self, database: str, name: str, owner: str = None, present: bool = True, setup: "Setup" = None):
        super().__init__(name=name, present=present, setup=setup)
        self.database = database
        self.owner = owner
        self.dependencies.add(Database(self.database))
        if self.owner:
            self.dependencies.add(self.setup.resolve_owner(self.owner))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.database}.{self.name})"

    @property
    def type_key(self) -> Hashable:
        return self.__class__, self.database

    def add_to_graph(self, graph: Graph):
        super().add_to_graph(graph)
        if self.owner:
            SchemaOwner(
                database=self.database, schema=self.name, owner=self.owner,
                present=self.present, setup=self.setup,
            ).add_to_graph(graph)

    def stmts_to_create(self):
        yield CreateStatement(self, database=self.database)

    def stmts_to_drop(self):
        yield DropStatement(self, database=self.database)


class SchemaOwner(ObjectLink):
    database: str
    schema: str
    owner: str

    def __init__(self, database: str, schema: str, owner: str, present: bool = True, setup: "Setup" = None):
        super().__init__(present=present, setup=setup)
        self.database = database
        self.schema = schema
        self.owner = owner
        self.dependencies.add(Schema(database=self.database, name=self.schema))
        self.dependencies.add(self.setup.resolve_owner(self.owner))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.database}.{self.schema}+{self.owner})"

    @property
    def type_key(self):
        return self.__class__, self.database

    def stmts_to_create(self):
        yield TextStatement(f"ALTER SCHEMA {self.schema} OWNER TO {self.owner}", database=self.database)


class State(str):
    # The object currently exists
    IS_PRESENT: "State"

    # The object does not currently exist
    IS_ABSENT: "State"

    # The object currently exists and supports changes and we have detected a change.
    IS_DIFFERENT: "State"

    # The object may exist or may be missing, we do not support detection of its state,
    # need to apply the state / issue create statements.
    IS_UNKNOWN: "State"

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


State.IS_PRESENT = State("IS_PRESENT")
State.IS_ABSENT = State("IS_ABSENT")
State.IS_DIFFERENT = State("IS_DIFFERENT")
State.IS_UNKNOWN = State("IS_UNKNOWN")


class ServerState:
    def __init__(self):
        self.databases = {}
        self.schemas = collections.defaultdict(dict)
        self.groups = {}
        self.users = {}
        self.group_users = collections.defaultdict(list)
        self.user_groups = collections.defaultdict(list)


class Setup:
    def __init__(self, master_connection: Connection = None):
        self._objects: Dict[Hashable, Object] = {}

        self._server_state: ServerState = None

        # Master connection
        self._mc: Connection = master_connection

        # Connections by database except the master connection which is self._mc
        self._connections: Dict[str, Connection] = {}

    @property
    def master_user(self):
        """
        Master user becomes the owner of objects owned by to be dropped owners
        for which no new owner is set.
        """
        return self._mc.username

    @property
    def managed_databases(self) -> List[str]:
        """
        List of database names that this setup manages.
        """
        return [d.name for d in self._objects.values() if isinstance(d, Database)]

    def register(self, obj: Object):
        assert obj not in self
        assert not isinstance(obj, ObjectLink)

        # Check dependencies
        # We cannot check dependencies of ObjectLink because they are not stored in self._objects.
        # We cannot check dep.present because the dependency objects don't know anything about the
        # desired state.
        for dep in obj.dependencies:
            if dep not in self:
                raise ValueError(f"{obj} depends on {dep} but it is not managed by this setup")
            if obj.present and not self.get(dep).present:
                raise ValueError(f"{obj} depends on {dep} but it is marked as not present")

        self._objects[obj.key] = obj

    def get(self, obj_or_key: Union[Object, Hashable]) -> Optional[Object]:
        if isinstance(obj_or_key, ObjectLink):
            raise TypeError(f"Expected instance of {Object} or a key, got an instance of {ObjectLink}")
        if isinstance(obj_or_key, Object):
            return self._objects.get(obj_or_key.key)
        return self._objects.get(obj_or_key)

    def __contains__(self, obj_or_key: Union[Object, Hashable]):
        """
        Returns True if the passed object or the passed key is managed by this Setup.
        This does not handle ObjectLinks.
        """
        if isinstance(obj_or_key, ObjectLink):
            raise TypeError(f"Expected instance of {Object} or a key, got an instance of {ObjectLink}")
        if isinstance(obj_or_key, Object):
            return obj_or_key.key in self._objects
        return obj_or_key in self._objects

    def group(self, name, **kwargs) -> Group:
        g = Group(name, **kwargs, setup=self)
        self.register(g)
        return g

    def user(self, name, **kwargs) -> User:
        u = User(name, **kwargs, setup=self)
        self.register(u)
        return u

    def database(self, name, **kwargs) -> Database:
        d = Database(name, **kwargs, setup=self)
        self.register(d)
        return d

    def schema(self, name, *, database, **kwargs) -> Schema:
        s = Schema(name=name, database=database, **kwargs, setup=self)
        self.register(s)
        return s

    def resolve_owner(self, owner: str):
        group = Group(owner)
        user = User(owner)
        if group in self:
            return group
        elif user in self:
            return user
        raise ValueError(
            f"Ambiguous owner {owner!r} - "
            f"declare it as Group or User before referencing it as owner of another object"
        )

    def generate_graph(self) -> Graph:
        g = Graph()
        for obj in self._objects.values():
            obj.add_to_graph(g)
        return g

    def topological_order(self) -> List[Object]:
        return [vertex.value for vertex in self.generate_graph().topological_sort_by_kahn()]

    def get_connection(self, database: str = None) -> Connection:
        if database is None or database == self._mc.database:
            return self._mc
        if database not in self._connections:
            self._connections[database] = self._mc.clone(database=database)
        return self._connections[database]

    def _load_server_state(self):
        self._server_state = ServerState()

        for raw in self._mc.execute("SELECT groname AS name FROM pg_group").get_all("name"):
            if raw["name"].startswith("pg_"):
                continue
            self._server_state.groups[raw["name"]] = raw

        for raw in self._mc.execute("SELECT rolname AS name FROM pg_roles").get_all("name"):
            if raw["name"].startswith("pg_") or raw["name"] in self._server_state.groups:
                # pg_roles contains both users and groups so the only way to distinguish
                # them is by checking which ones are not groups.
                continue
            self._server_state.users[raw["name"]] = raw

        raw_rows = self._mc.execute(f"""
            SELECT
            pg_group.groname,
            pg_roles.rolname
            FROM pg_group
            LEFT JOIN pg_roles ON pg_roles.oid = ANY(pg_group.grolist)
            ORDER BY pg_group.groname, pg_roles.rolname
        """).get_all("groname", "rolname")
        for raw in raw_rows:
            if raw["rolname"]:
                self._server_state.group_users[raw["groname"]].append(raw["rolname"])
                self._server_state.user_groups[raw["rolname"]].append(raw["groname"])

        raw_rows = self._mc.execute(f"""
            SELECT d.datname as name,
            pg_catalog.pg_get_userbyid(d.datdba) as owner
            FROM pg_catalog.pg_database d
        """).get_all("name", "owner")
        for raw in raw_rows:
            self._server_state.databases[raw["name"]] = raw

        for datname in self._server_state.databases.keys():
            if datname not in self.managed_databases:
                # Do not attempt to connect to or in any other way manage
                # databases which are not mentioned in the objects.
                continue
            conn = self.get_connection(datname)
            raw_rows = conn.execute(f"""
                SELECT
                pg_namespace.nspname AS name,
                pg_roles.rolname AS owner
                FROM pg_namespace
                LEFT JOIN pg_roles ON pg_namespace.nspowner = pg_roles.oid
                WHERE pg_namespace.nspname != 'information_schema' AND
                pg_namespace.nspname NOT LIKE 'pg_%'
                ORDER BY pg_namespace.nspname
            """).get_all("name", "owner")
            for raw in raw_rows:
                self._server_state.schemas[datname][raw["name"]] = {
                    "database": datname, "name": raw["name"], "owner": raw["owner"],
                }

    def get_current_state(self, obj: Object) -> State:
        """
        Queries database cluster and returns the current state of the object (one of the CurrentState values).
        """

        if isinstance(obj, Database):
            if obj.name in self._server_state.databases:
                return State.IS_PRESENT
            else:
                return State.IS_ABSENT

        elif isinstance(obj, DatabaseOwner):
            if obj.database not in self._server_state.databases:
                return State.IS_ABSENT
            elif self._server_state.databases[obj.database]["owner"] == obj.owner:
                return State.IS_PRESENT
            else:
                # TODO (IS_DIFFERENT)
                # Technically, it is IS_DIFFERENT, but for DatabaseOwner IS_ABSENT is okay
                # and we don't support IS_DIFFERENT yet
                return State.IS_ABSENT

        elif isinstance(obj, User):
            if obj.name in self._server_state.users:
                return State.IS_PRESENT
            else:
                return State.IS_ABSENT

        elif isinstance(obj, Group):
            if obj.name in self._server_state.groups:
                return State.IS_PRESENT
            else:
                return State.IS_ABSENT

        elif isinstance(obj, GroupUser):
            if obj.user in self._server_state.group_users[obj.group]:
                return State.IS_PRESENT
            else:
                return State.IS_ABSENT

        elif isinstance(obj, Schema):
            if obj.database in self._server_state.schemas:
                if obj.name in self._server_state.schemas[obj.database]:
                    return State.IS_PRESENT
            return State.IS_ABSENT

        elif isinstance(obj, SchemaOwner):
            if obj.database in self._server_state.schemas:
                if obj.schema in self._server_state.schemas[obj.database]:
                    current = self._server_state.schemas[obj.database][obj.schema]
                    if obj.owner == current["owner"]:
                        return State.IS_PRESENT
                    else:
                        # TODO (IS_DIFFERENT)
                        # It's okay to report it as absent,
                        # we don't support IS_DIFFERENT yet
                        return State.IS_ABSENT
            return State.IS_ABSENT

        log.warning(f"Requested current state for unsupported object type {obj.__class__}, returning IS_ABSENT")
        return State.IS_ABSENT

    def generate_stmts(self) -> Generator[Statement, None, None]:
        objects = self.topological_order()

        log.debug("Graph in topological order to CREATE objects:")
        for i, obj in enumerate(objects):
            log.debug(f"  {str(i+1).zfill(2)} {obj} present={obj.present}")

        # CREATE objects in topological order
        for obj in objects:
            current_state = self.get_current_state(obj)

            if current_state.is_absent and obj.present:
                # Object should be created
                yield from obj.stmts_to_create()

            elif current_state.is_unknown and obj.present:
                yield from obj.stmts_to_create()

        # "Maintain" objects in topological order
        for obj in objects:
            if obj.present:
                yield from obj.stmts_to_maintain()

        log.debug("Graph in reverse topological order to DROP objects:")
        for i, obj in enumerate(reversed(objects)):
            log.debug(f"  {str(i + 1).zfill(2)} {obj} present={obj.present}")

        # DROP objects in reverse topological order
        for obj in reversed(objects):
            current_state = self.get_current_state(obj)

            if current_state.is_present and not obj.present:
                # Object should be dropped
                yield from obj.stmts_to_drop()

            elif current_state.is_unknown and not obj.present:
                yield from obj.stmts_to_drop()

    def execute(self):
        self._load_server_state()

        for stmt in self.generate_stmts():
            if stmt.is_on_all_databases:
                for datname in self.managed_databases:
                    # Not all statements can always be executed on all databases because they may not exist.
                    # Checking just the server state is not sufficient because:
                    # - database may not have existed originally, but exists by the time the statement runs.
                    # - database may have existed originally, but no longer exists.
                    # Therefore "present" is the best indicator of whether we should attempt this.
                    database = self.get(Database(datname))
                    if database and database.present:
                        self.get_connection(database=datname).execute(stmt.query, *stmt.params)
                    else:
                        log.info(f"Skipping statement {stmt} on non-existent database {datname!r}")
            else:
                conn = self.get_connection(database=stmt.database)

                # Before attempting to drop a database, must close the connection.
                # (a connection was acquired earlier for each database to load its schemas)
                if isinstance(stmt, DropStatement) and isinstance(stmt.obj, Database):
                    self.get_connection(stmt.obj.name).close()

                conn.execute(stmt.query, *stmt.params)
