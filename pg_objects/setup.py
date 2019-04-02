import collections
import logging
from typing import Dict, Hashable, List, Optional, Union, Generator

from .connection import Connection
from .graph import Graph
from .objects.base import Object, ObjectState, SetupAbc, ObjectLink, ConnectionManager
from .objects.database import Database, DatabaseOwner, DatabasePrivilege
from .objects.default_privilege import DefaultPrivilege
from .objects.role import User, Group, GroupUser
from .objects.schema import SchemaPrivilege, SchemaTablesPrivilege, Schema, SchemaOwner
from .state import State
from .statements import Statement, TransactionOfStatements, DropStatement


log = logging.getLogger(__name__)


class ServerState(State):
    def __init__(self, connection_manager: ConnectionManager):
        super().__init__(connection_manager=connection_manager)

        self.databases = {}

        # [database][schema] => {}
        self.schemas = collections.defaultdict(dict)

        # [database][schema][grantee] => Set[privileges]
        self.schema_privileges = collections.defaultdict(
            lambda: collections.defaultdict(
                lambda: collections.defaultdict(set)
            )
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
            return ObjectState.IS_UNKNOWN
        return getter(obj)

    def get_database(self, obj: Database):
        return ObjectState.IS_PRESENT if obj.name in self.databases else ObjectState.IS_ABSENT

    def get_databaseowner(self, obj: DatabaseOwner):
        if obj.database not in self.databases:
            return ObjectState.IS_ABSENT
        elif self.databases[obj.database]["owner"] == obj.owner:
            return ObjectState.IS_PRESENT
        else:
            # TODO (IS_DIFFERENT)
            # Technically, it is IS_DIFFERENT, but for DatabaseOwner IS_ABSENT is okay
            # and we don't support IS_DIFFERENT yet
            return ObjectState.IS_ABSENT

    def get_schemaprivilege(self, obj: SchemaPrivilege) -> ObjectState:
        sp = self.schema_privileges
        if obj.database in sp:
            if obj.schema in sp[obj.database]:
                if obj.grantee in sp[obj.database][obj.schema]:
                    if obj.privileges == sp[obj.database][obj.schema][obj.grantee]:
                        return ObjectState.IS_PRESENT
                    else:
                        return ObjectState.IS_DIFFERENT
        return ObjectState.IS_ABSENT

    def get_schematablesprivilege(self, obj: SchemaTablesPrivilege) -> ObjectState:
        stp = self.schema_tables_privileges
        if obj.database in stp:
            if obj.schema in stp[obj.database]:
                tables = self.schema_tables[obj.database][obj.schema]
                if obj.grantee in stp[obj.database][obj.schema]:
                    # Have to check that privileges for each existing table match the expected ones
                    if all(stp[obj.database][obj.schema][obj.grantee][t] == obj.privileges for t in tables):
                        return ObjectState.IS_PRESENT
                    else:
                        return ObjectState.IS_DIFFERENT
        return ObjectState.IS_ABSENT

    def get_defaultprivilege(self, obj: DefaultPrivilege) -> ObjectState:
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
            return ObjectState.IS_ABSENT
        if isinstance(priv, SchemaTablesPrivilege):
            if priv.database not in self.schemas:
                return ObjectState.IS_ABSENT
            if priv.schema not in self.schemas[priv.database]:
                return ObjectState.IS_ABSENT
        return ObjectState.IS_UNKNOWN

    def get_user(self, obj: User) -> ObjectState:
        return ObjectState.IS_PRESENT if obj.name in self.users else ObjectState.IS_ABSENT

    def get_group(self, obj: Group) -> ObjectState:
        return ObjectState.IS_PRESENT if obj.name in self.groups else ObjectState.IS_ABSENT

    def get_groupuser(self, obj: GroupUser) -> ObjectState:
        return ObjectState.IS_PRESENT if obj.user in self.group_users[obj.group] else ObjectState.IS_ABSENT

    def get_schema(self, obj: Schema) -> ObjectState:
        if obj.database in self.schemas:
            if obj.name in self.schemas[obj.database]:
                return ObjectState.IS_PRESENT
        return ObjectState.IS_ABSENT

    def get_schemaowner(self, obj: SchemaOwner) -> ObjectState:
        if obj.database in self.schemas:
            if obj.schema in self.schemas[obj.database]:
                current = self.schemas[obj.database][obj.schema]
                if obj.owner == current["owner"]:
                    return ObjectState.IS_PRESENT
                else:
                    # TODO (IS_DIFFERENT)
                    # It's okay to report it as absent,
                    # we don't support IS_DIFFERENT yet
                    return ObjectState.IS_ABSENT
        return ObjectState.IS_ABSENT


class Setup(SetupAbc):
    def __init__(self, master_connection: Connection = None):
        self._objects: Dict[Hashable, Object] = {}

        self._server_state: ServerState = None

        self.connection_manager = ConnectionManager(master_connection=master_connection)

        for obj in self.get_implicit_objects():
            self.register(obj)

    @property
    def _mc(self) -> Connection:
        return self.connection_manager.master_connection

    def get_connection(self, database: str = None) -> Connection:
        return self.connection_manager.get_connection(database=database)

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

    def database_privilege(self, **kwargs):

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

    def _load_server_state(self):
        state = ServerState(connection_manager=self.connection_manager)
        state.load_all()

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

    def get_current_state(self, obj: Object) -> ObjectState:
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
                        assert stmt.database is None or stmt.database == connection.database
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
