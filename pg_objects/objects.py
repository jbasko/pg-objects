import collections
import hashlib
import logging
from typing import List, Generator, Hashable, Dict, Tuple, Union, ClassVar, Optional, Set, Collection, Type

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

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        return isinstance(self, type(other)) and self.key == other.key

    def __repr__(self):
        return f"<{self.key}>"

    def resolve_owner(self, owner: str) -> "Role":
        if self.setup is None:
            return Group(owner)
        return self.setup.resolve_owner(owner)

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

    FORBIDDEN_ROLES = {"public", "postgres"}

    def stmts_to_create(self):
        if self.name.lower() in self.FORBIDDEN_ROLES or self.name.startswith("pg_"):
            return
        yield CreateStatement(self)

    def stmts_to_drop(self):
        if self.name.lower()  in self.FORBIDDEN_ROLES or self.name.startswith("pg_"):
            return

        # TODO Add "reassign_to" attribute which would be used in these cases
        yield TextStatement(
            query=f"REASSIGN OWNED BY {self.name} TO {self.setup.master_user}",
            database=Statement.ALL_DATABASES,
        )
        yield TextStatement(
            query=f"REVOKE ALL ON SCHEMA public FROM {self.name}",
            database=Statement.ALL_DATABASES
        )
        yield TextStatement(
            query=f"REVOKE ALL ON SCHEMA public FROM {self.name}",
            database=self.setup.master_database,
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
        # If password is not set, the password is not updated and is not disabled either.
        password_sql = "LOGIN"
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
            self.dependencies.add(self.resolve_owner(self.owner))

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
        # We don't allow public access to managed databases.
        # TODO At the moment there is no cleaner way to do this
        # TODO because we are not loading current privileges of public group
        # TODO as it does not appear in pg_roles.
        # TODO Also, a new database wouldn't have existed at the time when
        # TODO we load server state so we wouldn't have detected state change
        # TODO if we requested an implicit DatabasePrivilege to be absent.
        yield TextStatement(f"""
            REVOKE ALL PRIVILEGES
            ON DATABASE {self.name}
            FROM GROUP public
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
            self.dependencies.add(self.resolve_owner(self.owner))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.database}.{self.name})"

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
        self.dependencies.add(self.resolve_owner(self.owner))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.database}.{self.schema}+{self.owner})"

    def stmts_to_create(self):
        yield TextStatement(f"ALTER SCHEMA {self.schema} OWNER TO {self.owner}", database=self.database)


class DatabasePrivilege(Object):
    database: str
    grantee: str
    privileges: Set[str]

    CONNECT = "CONNECT"
    CREATE = "CREATE"
    TEMPORARY = "TEMPORARY"
    ALL = {CONNECT, CREATE, TEMPORARY}

    def __init__(
        self,
        database: str, grantee: str, privileges: Union[str, Collection[str]],
        present: bool = True, setup: "Setup" = None,
    ):
        super().__init__(present=present, setup=setup)
        self.database = database
        self.grantee = grantee
        self.privileges = parse_privileges(privileges, obj_type=self.__class__)
        self.dependencies.add(Database(self.database))
        self.dependencies.add(self.resolve_owner(self.grantee))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.grantee}@{self.database}:{','.join(sorted(self.privileges))})"

    def stmts_to_create(self):
        if self.privileges != DatabasePrivilege.ALL:
            # Revoke all privileges before applying the necessary privileges
            yield TextStatement(f"""
                REVOKE ALL ON DATABASE {self.database}
                FROM {self.grantee}
            """)
        yield TextStatement(f"""
            GRANT {', '.join(self.privileges)}
            ON DATABASE {self.database}
            TO {self.grantee}
        """)

    def stmts_to_drop(self):
        yield TextStatement(f"""
            REVOKE {', '.join(self.privileges)}
            ON DATABASE {self.database}
            FROM {self.grantee}
        """)


class SchemaPrivilege(Object):
    database: str
    schema: str
    grantee: str
    privileges: Set[str]

    CREATE = "CREATE"
    USAGE = "USAGE"
    ALL = {CREATE, USAGE}

    def __init__(
        self,
        database: str, schema: str, grantee: str, privileges: Union[str, Collection[str]],
        present: bool = True, setup: "Setup" = None,
    ):
        super().__init__(present=present, setup=setup)
        self.database = database
        self.schema = schema
        self.grantee = grantee
        self.privileges = parse_privileges(privileges, obj_type=self.__class__)
        self.dependencies.add(Database(self.database))
        self.dependencies.add(Schema(database=self.database, name=self.schema))
        self.dependencies.add(self.resolve_owner(self.grantee))

    @property
    def key(self):
        return (
            f"{self.__class__.__name__}({self.grantee}@{self.database}.{self.schema}:"
            f"{','.join(sorted(self.privileges))})"
        )

    def stmts_to_create(self):
        if self.privileges != self.ALL:
            # Revoke all privileges before applying the necessary privileges
            yield TextStatement(
                query=f"REVOKE ALL ON SCHEMA {self.schema} FROM {self.grantee}",
                database=self.database,
            )

        yield TextStatement(f"""
            GRANT {', '.join(self.privileges)}
            ON SCHEMA {self.schema} TO {self.grantee}
        """, database=self.database)

    def stmts_to_drop(self):
        yield TextStatement(
            query=f"REVOKE ALL ON SCHEMA {self.schema} FROM {self.grantee}",
            database=self.database,
        )


class SchemaTablesPrivilege(SchemaPrivilege):
    """
    SchemaTablesPrivilege applies to ALL TABLES of a schema.
    We do not intend to support custom privileges on individual tables.

    Schema "public" is accessible to anyone who has access to the database and we don't manage
    it yet.
    """

    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    TRUNCATE = "TRUNCATE"
    REFERENCES = "REFERENCES"
    TRIGGER = "TRIGGER"
    ALL = {SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER}

    def stmts_to_create(self):
        if self.privileges != self.ALL:
            yield TextStatement(
                query=f"""
                    REVOKE ALL ON ALL TABLES
                    IN SCHEMA {self.schema}
                    FROM {self.grantee}
                """,
                database=self.database,
            )

        yield TextStatement(
            query=f"""
                GRANT {', '.join(self.privileges)} ON ALL TABLES
                IN SCHEMA {self.schema}
                TO {self.grantee}
            """,
            database=self.database,
        )

        # TODO Continue here.
        # TODO The problem is as soon as you create default privileges
        # TODO you need to drop them when you are dropping roles or
        # TODO dropping roles will start to fail.

        # # By default, any table created by the owner of the schema in this schema
        # # should have the same access rights as the ones being granted.
        # schema_owner = self.setup.get(Schema(database=self.database, name=self.schema)).owner
        # yield TextStatement(
        #     query=f"""
        #         ALTER DEFAULT PRIVILEGES
        #         FOR ROLE {schema_owner}
        #         IN SCHEMA {self.schema}
        #         GRANT {', '.join(self.privileges)} ON ALL TABLES
        #         TO {self.grantee}
        #     """,
        #     database=self.database,
        # )

    def stmts_to_drop(self):
        yield TextStatement(
            query=f"""
                REVOKE {', '.join(self.privileges)} ON ALL TABLES
                IN SCHEMA {self.schema}
                FROM {self.grantee}
            """,
            database=self.database,
        )


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

        # [database][grantee] => Set[privileges]
        self.database_privileges = collections.defaultdict(
            lambda: collections.defaultdict(set)
        )

        # [database][schema] => {}
        self.schemas = collections.defaultdict(dict)

        # [database][schema][grantee] => Set[privileges]
        self.schema_privileges = collections.defaultdict(
            lambda: collections.defaultdict(
                lambda: collections.defaultdict(set)
            )
        )

        # [database][schema][table] => {}
        self.schema_tables = collections.defaultdict(
            lambda: collections.defaultdict(dict)
        )

        # [database][schema][grantee][table] => Set[privileges]
        self.schema_tables_privileges = collections.defaultdict(
            lambda: collections.defaultdict(
                lambda: collections.defaultdict(
                    lambda: collections.defaultdict(set)
                )
            )
        )
        self.groups = {}
        self.users = {}
        self.group_users = collections.defaultdict(list)
        self.user_groups = collections.defaultdict(list)

    def pprint(self):
        from pprint import pprint
        for k, v in self.__dict__.items():
            print(k, ":")
            pprint(dict(v), indent=2)

    def get(self, obj: Object):
        getter = getattr(self, f"get_{obj.__class__.__name__.lower()}", None)
        if getter is None:
            log.warning(f"Requested current state for unsupported object type {obj.__class__}, returning IS_UNKNOWN")
            return State.IS_UNKNOWN
        return getter(obj)

    def get_database(self, obj: Database):
        return State.IS_PRESENT if obj.name in self.databases else State.IS_ABSENT

    def get_databaseowner(self, obj: DatabaseOwner):
        if obj.database not in self.databases:
            return State.IS_ABSENT
        elif self.databases[obj.database]["owner"] == obj.owner:
            return State.IS_PRESENT
        else:
            # TODO (IS_DIFFERENT)
            # Technically, it is IS_DIFFERENT, but for DatabaseOwner IS_ABSENT is okay
            # and we don't support IS_DIFFERENT yet
            return State.IS_ABSENT

    def get_databaseprivilege(self, obj: DatabasePrivilege) -> State:
        if obj.database in self.database_privileges:
            if obj.grantee in self.database_privileges[obj.database]:
                if obj.privileges == self.database_privileges[obj.database][obj.grantee]:
                    return State.IS_PRESENT
                else:
                    return State.IS_DIFFERENT
        return State.IS_ABSENT

    def get_schemaprivilege(self, obj: SchemaPrivilege) -> State:
        sp = self.schema_privileges
        if obj.database in sp:
            if obj.schema in sp[obj.database]:
                if obj.grantee in sp[obj.database][obj.schema]:
                    if obj.privileges == sp[obj.database][obj.schema][obj.grantee]:
                        return State.IS_PRESENT
                    else:
                        return State.IS_DIFFERENT
        return State.IS_ABSENT

    def get_schematablesprivilege(self, obj: SchemaTablesPrivilege) -> State:
        stp = self.schema_tables_privileges
        if obj.database in stp:
            if obj.schema in stp[obj.database]:
                tables = self.schema_tables[obj.database][obj.schema]
                if obj.grantee in stp[obj.database][obj.schema]:
                    # Have to check that privileges for each existing table match the expected ones
                    if all(stp[obj.database][obj.schema][obj.grantee][t] == obj.privileges for t in tables):
                        return State.IS_PRESENT
                    else:
                        return State.IS_DIFFERENT
        return State.IS_ABSENT

    def get_user(self, obj: User) -> State:
        return State.IS_PRESENT if obj.name in self.users else State.IS_ABSENT

    def get_group(self, obj: Group) -> State:
        return State.IS_PRESENT if obj.name in self.groups else State.IS_ABSENT

    def get_groupuser(self, obj: GroupUser) -> State:
        return State.IS_PRESENT if obj.user in self.group_users[obj.group] else State.IS_ABSENT

    def get_schema(self, obj: Schema) -> State:
        if obj.database in self.schemas:
            if obj.name in self.schemas[obj.database]:
                return State.IS_PRESENT
        return State.IS_ABSENT

    def get_schemaowner(self, obj: SchemaOwner) -> State:
        if obj.database in self.schemas:
            if obj.schema in self.schemas[obj.database]:
                current = self.schemas[obj.database][obj.schema]
                if obj.owner == current["owner"]:
                    return State.IS_PRESENT
                else:
                    # TODO (IS_DIFFERENT)
                    # It's okay to report it as absent,
                    # we don't support IS_DIFFERENT yet
                    return State.IS_ABSENT
        return State.IS_ABSENT


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


class Setup:
    def __init__(self, master_connection: Connection = None):
        self._objects: Dict[Hashable, Object] = {}

        self._server_state: ServerState = None

        # Master connection
        self._mc: Connection = master_connection

        # Connections by database except the master connection which is self._mc
        self._connections: Dict[str, Connection] = {}

        for obj in self.get_implicit_objects():
            self.register(obj)

    def get_implicit_objects(self) -> List[Object]:
        """
        Returns a list of objects that are not managed (created, updated, dropped) by us,
        but they may be referenced by managed objects and therefore need to be in the
        object graph.
        """
        return [
            # public group is the group to which all roles belong.
            # We need to revoke some privileges which are assigned to it by default
            # in all new databases.
            Group(name="public"),
        ]

    @property
    def master_user(self) -> str:
        """
        Master user becomes the owner of objects owned by to be dropped owners
        for which no new owner is set.
        """
        return self._mc.username

    @property
    def master_database(self) -> str:
        """
        Master database (postgres) is not managed, but some revokes should be issued in that.
        """
        return self._mc.database

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

    def database_privilege(self, **kwargs) -> DatabasePrivilege:
        dp = DatabasePrivilege(**kwargs, setup=self)
        self.register(dp)
        return dp

    def schema(self, name, *, database, **kwargs) -> Schema:
        s = Schema(name=name, database=database, **kwargs, setup=self)
        self.register(s)
        return s

    def schema_privilege(self, **kwargs) -> SchemaPrivilege:
        sp = SchemaPrivilege(**kwargs, setup=self)
        self.register(sp)
        return sp

    def schema_tables_privilege(self, **kwargs) -> SchemaTablesPrivilege:
        stp = SchemaTablesPrivilege(**kwargs, setup=self)
        self.register(stp)
        return stp

    def resolve_owner(self, owner: str):
        group = Group(owner)
        user = User(owner)
        if group in self:
            return group
        elif user in self:
            return user
        if owner.lower() == "public":
            return Group("public")
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
        state = ServerState()

        for raw in self._mc.execute("SELECT groname AS name FROM pg_group").get_all("name"):
            if raw["name"].startswith("pg_"):
                continue
            state.groups[raw["name"]] = raw

        for raw in self._mc.execute("SELECT rolname AS name FROM pg_roles").get_all("name"):
            if raw["name"].startswith("pg_") or raw["name"] in state.groups:
                # pg_roles contains both users and groups so the only way to distinguish
                # them is by checking which ones are not groups.
                continue
            state.users[raw["name"]] = raw

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
                state.group_users[raw["groname"]].append(raw["rolname"])
                state.user_groups[raw["rolname"]].append(raw["groname"])

        raw_rows = self._mc.execute(f"""
            SELECT d.datname as name,
            pg_catalog.pg_get_userbyid(d.datdba) as owner
            FROM pg_catalog.pg_database d
        """).get_all("name", "owner")
        for raw in raw_rows:
            state.databases[raw["name"]] = raw

        for datname in state.databases.keys():
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
                state.schemas[datname][raw["name"]] = {
                    "database": datname, "name": raw["name"], "owner": raw["owner"],
                }

        for priv_type in DatabasePrivilege.ALL:
            raw_rows = self._mc.execute(f"""
                SELECT
                    r.rolname,
                    (
                        SELECT STRING_AGG(d.datname, ',' ORDER BY d.datname) 
                        FROM pg_database d 
                        WHERE HAS_DATABASE_PRIVILEGE(r.rolname, d.datname, %s)
                        AND NOT d.datname LIKE 'template%%' AND d.datname != 'postgres'
                    ) AS databases
                FROM pg_roles r
                WHERE NOT r.rolcanlogin AND NOT (r.rolname LIKE 'pg_%%')
                ORDER BY r.rolname
            """, priv_type).get_all("rolname", "databases")
            for raw in raw_rows:
                if not raw["databases"]:
                    continue
                for datname in raw["databases"].split(","):
                    state.database_privileges[datname][raw["rolname"]].add(priv_type)

        for datname in state.databases.keys():
            if datname not in self.managed_databases:
                continue
            conn = self.get_connection(datname)

            #
            # Load schema privileges
            #
            for priv_type in SchemaPrivilege.ALL:
                raw_rows = conn.execute(f"""
                    SELECT
                        r.rolname,
                        (
                            SELECT STRING_AGG(s.nspname, ',' ORDER BY s.nspname)
                            FROM pg_namespace s 
                            WHERE HAS_SCHEMA_PRIVILEGE(r.rolname, s.nspname, %s)
                            AND s.nspname != 'information_schema'
                            AND NOT s.nspname LIKE 'pg_%%'
                        ) AS schemas
                    FROM pg_roles r
                    WHERE NOT r.rolcanlogin AND NOT (r.rolname LIKE 'pg_%%')
                    ORDER BY r.rolname
                """, priv_type).get_all("rolname", "schemas")
                for raw in raw_rows:
                    if not raw["schemas"]:
                        continue
                    for schemaname in raw["schemas"].split(","):
                        state.schema_privileges[datname][schemaname][raw["rolname"]].add(priv_type)

            #
            # Load schema tables
            #
            raw_rows = conn.execute(f"""
                SELECT schemaname, tablename, tableowner FROM pg_tables
                WHERE schemaname != 'information_schema' AND NOT schemaname LIKE 'pg_%%' 
            """).get_all("schemaname", "tablename", "tableowner")
            for raw in raw_rows:
                state.schema_tables[datname][raw["schemaname"]][raw["tablename"]] = {
                    "database": datname,
                    "schema": raw["schemaname"],
                    "name": raw["tablename"],
                    "owner": raw["tableowner"],
                }

            #
            # Load schema tables privileges
            #
            raw_rows = conn.execute(f"""
                SELECT
                grantee, table_schema, table_name, STRING_AGG(privilege_type, ',') AS privileges
                FROM information_schema.role_table_grants
                WHERE table_schema != 'information_schema' AND NOT table_schema LIKE 'pg_%'
                GROUP BY grantee, table_schema, table_name;
            """).get_all("grantee", "table_schema", "table_name", "privileges")
            for raw in raw_rows:
                if not raw["privileges"]:
                    continue
                state.schema_tables_privileges[datname][raw["table_schema"]][raw["grantee"]][raw["table_name"]] = set(raw["privileges"].split(","))

        # TODO Return instead of storing on instance so that it could be reloaded
        self._server_state = state

    def get_current_state(self, obj: Object) -> State:
        """
        Queries database cluster and returns the current state of the object (one of the State values).
        """
        return self._server_state.get(obj)

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

            elif current_state.is_different and obj.present:
                yield from obj.stmts_to_update()

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
