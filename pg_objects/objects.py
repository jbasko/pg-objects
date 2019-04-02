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


class TransactionOfStatements(Statement):

    statements: List[Statement]

    def __init__(self, *statements, **kwargs):
        self.statements = statements
        self.database = kwargs.pop("database", None)
        assert not kwargs


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

    def resolve_role(self, rolname: str, present: bool = True) -> "Role":
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

    def _is_managed(self):
        if self.name.lower() in self.FORBIDDEN_ROLES:
            return False
        if self.name.lower().startswith("pg_"):
            return False
        if self.name == self.setup.master_user:
            return False
        return True

    def stmts_to_create(self):
        if not self._is_managed():
            return

        yield CreateStatement(self)

    def stmts_to_drop(self):
        if not self._is_managed():
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
    inherit: bool

    # Each user with inherit=False (which is the default setting and should not be changed unless
    # you are fully aware of the default privilege implications) requires an explicit list of
    # databases they are allowed to connect to because group's CONNECT privilege cannot or isn't passed to user.
    # Alternatively, you can explicitly declare the DatabasePrivilege for user in the setup.
    databases: Set[str]

    def __init__(
        self,
        name, password: str = None, groups: List[str] = None, inherit: bool = False, databases: Set[str] = None,
        present: bool = True, setup: "Setup" = None,
    ):
        super().__init__(name=name, present=present, setup=setup)
        self.password = password
        self.groups = groups or []
        self.inherit = inherit
        self.databases = set(databases) if databases else set()
        for group in self.groups:
            self.dependencies.add(Group(group))
        for datname in self.databases:
            self.dependencies.add(Database(datname))

    def add_to_graph(self, graph: Graph):
        super().add_to_graph(graph)
        for group in self.groups:
            GroupUser(
                group=group, user=self.name,
                present=self.present, setup=self.setup,
            ).add_to_graph(graph)

        # Through "databases" attribute user only gets CONNECT privilege.
        # Other privileges (CREATE, TEMPORARY) need to be assigned via group role
        # which user should then use to create objects (SET ROLE groupname).
        for datname in self.databases:
            DatabasePrivilege(
                database=datname,
                grantee=self.name,
                privileges=DatabasePrivilege.CONNECT,
                present=self.present,
                setup=self.setup,
            ).add_to_graph(graph)

    def stmts_to_maintain(self) -> Generator[Statement, None, None]:
        inherit_sql = "INHERIT" if self.inherit else "NOINHERIT"
        yield TextStatement(f"""
            ALTER USER {self.name}
            WITH NOCREATEDB NOSUPERUSER
            {inherit_sql}
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
            self.dependencies.add(self.resolve_role(self.owner))

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
        self.dependencies.add(setup.resolve_role(self.owner))

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
            self.dependencies.add(self.resolve_role(self.owner))

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
        self.dependencies.add(self.resolve_role(self.owner))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.database}.{self.schema}+{self.owner})"

    def stmts_to_create(self):
        yield TextStatement(f"ALTER SCHEMA {self.schema} OWNER TO {self.owner}", database=self.database)


class DefaultPrivilegeReady(Object):
    """
    Base class for privilege classes which support default privileges.
    """

    database: str
    schema: str
    grantee: str
    privileges: Set[str]

    ALL: ClassVar[Set[str]]

    def get_default_privilege_clause(self, privileges=None, present=None) -> str:
        """
        Returns GRANT or REVOKE in the form usable with ALTER DEFAULT PRIVILEGES.

        Pass privileges if you need to request privileges which are different from object's "privileges"
        attribute value. This is needed for REVOKE ALL statements.

        Pass present=True/False if you need to enforce a GRANT or REVOKE, otherwise
        the privilege's "present" attribute will be consulted. This is needed for REVOKE ALL statements.
        """
        raise NotImplementedError()


class DefaultPrivilege(Object):
    """
    DefaultPrivilege objects are expressed as a tuple of a privilege that supports default privileges
    and a grantor. Grantor is the role which will be creating new objects to which the privilege applies.
    """
    privilege: DefaultPrivilegeReady
    grantor: str

    def __init__(self, privilege: DefaultPrivilegeReady, grantor: str, present: bool = True, setup: "Setup" = None):
        super().__init__(name=None, present=present, setup=setup)
        self.privilege = privilege
        self.grantor = grantor
        self.dependencies.add(self.privilege)
        self.dependencies.add(self.resolve_role(self.grantor))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.grantor}:{self.privilege.key})"

    def _get_schema_sql(self):
        if self.privilege.schema:
            return f"IN SCHEMA {self.privilege.schema}"
        # TODO If schema is not specified, the default privilege applies to all schemas of the database.
        # TODO Allowing this needs careful thought and testing.
        raise ValueError("Global default privileges not supported yet")

    def _get_revoke_all_stmt(self):
        return TextStatement(
            query=f"""
                ALTER DEFAULT PRIVILEGES FOR ROLE {self.grantor}
                {self._get_schema_sql()}
                {self.privilege.get_default_privilege_clause(privileges=self.privilege.ALL, present=False)}
            """,
            database=self.privilege.database,
        )

    def stmts_to_maintain(self):

        def get_stmts():
            # First, revoke all default privileges so that we have a clean slate
            yield self._get_revoke_all_stmt()
            yield TextStatement(
                query=f"""
                    ALTER DEFAULT PRIVILEGES FOR ROLE {self.grantor}
                    {self._get_schema_sql()}
                    {self.privilege.get_default_privilege_clause()}
                """,
                database=self.privilege.database,
            )

        yield TransactionOfStatements(*get_stmts(), database=self.privilege.database)

    def stmts_to_drop(self):
        yield self._get_revoke_all_stmt()


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
        self.dependencies.add(self.resolve_role(self.grantee))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.grantee}@{self.database}:{','.join(sorted(self.privileges))})"

    def stmts_to_create(self):

        def get_stmts():
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

        yield TransactionOfStatements(*get_stmts())

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
        self.dependencies.add(self.resolve_role(self.grantee))

    @property
    def key(self):
        return (
            f"{self.__class__.__name__}({self.grantee}@{self.database}.{self.schema}:"
            f"{','.join(sorted(self.privileges))})"
        )

    def stmts_to_create(self):

        def get_stmts():
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

        yield TransactionOfStatements(*get_stmts(), database=self.database)

    def stmts_to_drop(self):
        yield TextStatement(
            query=f"REVOKE ALL ON SCHEMA {self.schema} FROM {self.grantee}",
            database=self.database,
        )


class SchemaTablesPrivilege(DefaultPrivilegeReady, SchemaPrivilege):
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
        def get_stmts():
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

        yield TransactionOfStatements(*get_stmts(), database=self.database)

    def stmts_to_drop(self):
        yield TextStatement(
            query=f"""
                REVOKE {', '.join(self.privileges)} ON ALL TABLES
                IN SCHEMA {self.schema}
                FROM {self.grantee}
            """,
            database=self.database,
        )

    def get_default_privilege_clause(self, privileges=None, present=None) -> str:
        present = self.present if (present is None) else present
        privileges = self.privileges if (privileges is None) else privileges
        return f"""
            {'GRANT' if present else 'REVOKE'}
            {', '.join(privileges)}
            ON TABLES
            {'TO' if present else 'FROM'}
            {self.grantee}
        """


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

    def get_defaultprivilege(self, obj: DefaultPrivilege) -> State:
        """
        TODO This is an incomplete implementation of current state of default privileges --
        TODO the actual state is not loaded, we just use the absence of schemas or roles
        TODO as an indicator that the default privilege is surely absent.
        TODO This is needed because the default state IS_UNKNOWN means that we should
        TODO attempt to revoke the privileges every time they are requested absent
        TODO but that would throw errors if schemas or roles don't exist.
        """
        priv = obj.privilege
        if obj.grantor not in self.groups and obj.grantor not in self.users:
            return State.IS_ABSENT
        if isinstance(priv, SchemaTablesPrivilege):
            if priv.database not in self.schemas:
                return State.IS_ABSENT
            if priv.schema not in self.schemas[priv.database]:
                return State.IS_ABSENT
        return State.IS_UNKNOWN

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

    @classmethod
    def from_definition(cls, definition: Dict, master_connection: Connection = None) -> "Setup":
        setup = cls(master_connection=master_connection)
        types = {}
        for k, v in globals().items():
            if isinstance(v, type) and issubclass(v, Object):
                types[k] = v
        for raw in definition["objects"]:
            obj_type_name = raw.pop("type")
            obj_type = types[obj_type_name]
            obj = obj_type(**raw, setup=setup)
            setup.register(obj)
        return setup

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
    def master_user(self) -> Optional[str]:
        """
        Master user becomes the owner of objects owned by to be dropped owners
        for which no new owner is set.
        """
        if self._mc:
            return self._mc.username
        return None

    @property
    def master_database(self) -> Optional[str]:
        """
        Master database (postgres) is not managed, but some revokes should be issued in that.
        """
        if self._mc:
            return self._mc.database
        return None

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

    def default_privilege(self, **kwargs) -> DefaultPrivilege:
        def_priv = DefaultPrivilege(**kwargs)
        self.register(def_priv)
        return def_priv

    def resolve_role(self, rolname: str, present: bool = True):
        group = Group(rolname, present=present)
        user = User(rolname, present=present)
        if group in self:
            return group
        elif user in self:
            return user
        if rolname.lower() == "public":
            return Group("public")
        raise ValueError(
            f"Ambiguous role {rolname!r} - "
            f"declare it as Group or User before referencing it in another object"
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

        # Always register the public group
        state.groups["public"] = {"name": "public"}

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
            WHERE pg_group.groname NOT LIKE 'pg_%%'
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
            WHERE d.datname NOT LIKE 'template%%'
            AND d.datname != 'postgres'
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

        #
        # Load database privileges
        #

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
                WHERE NOT (r.rolname LIKE 'pg_%%')
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

    def _generate_stmts(self) -> Generator[Statement, None, None]:
        objects = self.topological_order()

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

        # DROP objects in reverse topological order
        for obj in reversed(objects):
            current_state = self.get_current_state(obj)

            if current_state.is_present and not obj.present:
                # Object should be dropped
                yield from obj.stmts_to_drop()

            elif current_state.is_unknown and not obj.present:
                yield from obj.stmts_to_drop()

    def inspect(self, load_current_state=True):
        """
        Inspect objects of the graph.
        """
        if load_current_state:
            self._load_server_state()
        objects = self.topological_order()

        for i, obj in enumerate(objects):
            if load_current_state:
                current_state = self.get_current_state(obj)
            else:
                current_state = ""
            print(
                f"{str(i + 1).zfill(2)} {'PRESENT' if obj.present else '       '} "
                f"{current_state:10} "
                f"{obj.key}"
            )

    def execute(self, dry_run: bool = False):
        """
        Ensure the object graph in the setup matches that in the database cluster.

        If dry_run is set to True, it CONNECTS to the server and consults the current state,
        but no changes are applied.
        """

        def execute_stmt(connection: Connection, statement: Statement):
            if dry_run:
                if isinstance(statement, TransactionOfStatements):
                    for s in statement.statements:
                        connection.log_query(s.query, dry_run=True, database=s.database)
                else:
                    connection.log_query(statement.query, dry_run=True, database=statement.database)
                return

            # Before attempting to drop a database, must close the connection to that database.
            if isinstance(statement, DropStatement) and isinstance(statement.obj, Database):
                self.get_connection(statement.obj.name).close()

            # If a statement is a transaction, must execute it as one
            if isinstance(statement, TransactionOfStatements):
                with connection.begin() as tx:
                    for stmt in statement.statements:
                        assert stmt.database == connection.database
                        tx.execute(stmt.query, *stmt.params)
            else:
                connection.execute(statement.query, *statement.params)

        self._load_server_state()

        for stmt in self._generate_stmts():
            if stmt.is_on_all_databases:
                for datname in self.managed_databases:
                    # Not all statements can always be executed on all databases because they may not exist.
                    # Checking just the server state is not sufficient because:
                    # - database may not have existed originally, but exists by the time the statement runs.
                    # - database may have existed originally, but no longer exists.
                    # Therefore "present" is the best indicator of whether we should attempt this.
                    database = self.get(Database(datname))
                    if database and database.present:
                        execute_stmt(connection=self.get_connection(database=datname), statement=stmt)
                    else:
                        log.info(f"Skipping statement {stmt} on non-existent database {datname!r}")
            else:
                conn = self.get_connection(database=stmt.database)

                # Before attempting to drop a database, must close the connection.
                # (a connection was acquired earlier for each database to load its schemas)
                if isinstance(stmt, DropStatement) and isinstance(stmt.obj, Database):
                    self.get_connection(stmt.obj.name).close()

                execute_stmt(connection=conn, statement=stmt)
