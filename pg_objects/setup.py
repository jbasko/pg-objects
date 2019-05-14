import logging
from typing import Dict, Hashable, List, Optional, Union, Generator

from .connection import Connection
from .graph import Graph
from .objects.base import Object, ObjectState, SetupAbc, ObjectLink, ConnectionManager
from .objects.database import Database, DatabasePrivilege
from .objects.default_privilege import DefaultPrivilege
from .objects.role import User, Group
from .objects.schema import SchemaPrivilege, SchemaTablesPrivilege, Schema
from .registry import deserialise_object
from .state import State
from .statements import Statement, TransactionOfStatements, DropStatement


log = logging.getLogger(__name__)


class Setup(SetupAbc):
    def __init__(self, master_connection: Connection = None):
        self._objects: Dict[Hashable, Object] = {}

        self._server_state: State = None

        self.connection_manager = ConnectionManager(master_connection=master_connection)

        for obj in self.get_implicit_objects():
            self.register(obj)

    @property
    def mc(self) -> Connection:
        return self.connection_manager.master_connection

    def get_connection(self, database: str = None) -> Connection:
        return self.connection_manager.get_connection(database=database)

    @classmethod
    def from_definition(cls, definition: Dict, master_connection: Connection = None) -> "Setup":
        setup = cls(master_connection=master_connection)
        for raw in definition["objects"]:
            setup.register(deserialise_object(**raw, setup=setup))
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
            User(name=self.master_user),
        ]

    @property
    def master_user(self) -> Optional[str]:
        """
        Master user becomes the owner of objects owned by to be dropped owners
        for which no new owner is set.
        """
        if self.mc:
            return self.mc.username
        return None

    @property
    def master_database(self) -> Optional[str]:
        """
        Master database (postgres) is not managed, but some revokes should be issued in that.
        """
        if self.mc:
            return self.mc.database
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
        def_priv = DefaultPrivilege(**kwargs, setup=self)
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
        elif rolname == self.master_user:
            return User(rolname)
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
        state = State(connection_manager=self.connection_manager)
        state.load_all()

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
