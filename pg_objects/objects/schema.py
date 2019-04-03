import collections
from typing import Set, Union, Collection, Dict

from ..graph import Graph
from ..statements import CreateStatement, DropStatement, TextStatement, TransactionOfStatements
from .base import Object, SetupAbc, ObjectLink, parse_privileges, StateProviderAbc, ObjectState
from .database import Database
from .default_privilege import DefaultPrivilegeReady


class Schema(Object):
    database: str
    owner: str

    def __init__(self, database: str, name: str, owner: str = None, present: bool = True, setup: SetupAbc = None):
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

    def __init__(self, database: str, schema: str, owner: str, present: bool = True, setup: SetupAbc = None):
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
        present: bool = True, setup: SetupAbc = None,
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


class SchemaStateProvider(StateProviderAbc):

    # Provided by DatabaseStateProvider
    databases: Dict

    _ssp_schemas: Dict = None
    _ssp_schema_privileges: Dict = None

    @property
    def schemas(self):
        """
        [database][schema] => {}
        """
        if self._ssp_schemas is None:
            self.load_schemas()
        return self._ssp_schemas

    @property
    def schema_privileges(self) -> Dict[str, Dict[str, Dict[str, Set[str]]]]:
        """
        [database][schema][grantee] => Set[privileges]
        """
        if self._ssp_schema_privileges is None:
            self.load_schema_privileges()
        return self._ssp_schema_privileges

    def get_schema(self, obj: Schema) -> ObjectState:
        if obj.database in self._ssp_schemas:
            if obj.name in self._ssp_schemas[obj.database]:
                return ObjectState.IS_PRESENT
        return ObjectState.IS_ABSENT

    def get_schemaowner(self, obj: SchemaOwner) -> ObjectState:
        if obj.database in self._ssp_schemas:
            if obj.schema in self._ssp_schemas[obj.database]:
                current = self._ssp_schemas[obj.database][obj.schema]
                if obj.owner == current["owner"]:
                    return ObjectState.IS_PRESENT
                else:
                    return ObjectState.IS_DIFFERENT
        return ObjectState.IS_ABSENT

    def get_schemaprivilege(self, obj: SchemaPrivilege) -> ObjectState:
        sp = self._ssp_schema_privileges
        if obj.database in sp:
            if obj.schema in sp[obj.database]:
                if obj.grantee in sp[obj.database][obj.schema]:
                    if obj.privileges == sp[obj.database][obj.schema][obj.grantee]:
                        return ObjectState.IS_PRESENT
                    else:
                        return ObjectState.IS_DIFFERENT
        return ObjectState.IS_ABSENT

    def load_schemas(self):
        self._ssp_schemas = collections.defaultdict(dict)

        for datname in self.databases:
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
                self._ssp_schemas[datname][raw["name"]] = {
                    "database": datname, "name": raw["name"], "owner": raw["owner"],
                }

        return self._ssp_schemas

    def load_schema_privileges(self):
        self._ssp_schema_privileges = collections.defaultdict(
            lambda: collections.defaultdict(
                lambda: collections.defaultdict(set)
            )
        )

        # TODO This is imperfect as HAS_SCHEMA_PRIVILEGE checks effective privileges
        # TODO not actual privileges granted specifically to the role.

        for datname in self.databases:
            conn = self.get_connection(datname)
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
                        self._ssp_schema_privileges[datname][schemaname][raw["rolname"]].add(priv_type)


class SchemaTablesStateProvider(StateProviderAbc):

    # Provided by DatabaseStateProvider
    databases: Dict

    _stsp_schema_tables: Dict = None
    _stsp_schema_tables_privileges: Dict = None

    @property
    def schema_tables(self):
        """
        [database][schema][table] => {}
        """
        if self._stsp_schema_tables is None:
            self.load_schema_tables()
        return self._stsp_schema_tables

    @property
    def schema_tables_privileges(self):
        """
        [database][schema][grantee][table] => Set[privileges]
        """
        if self._stsp_schema_tables_privileges is None:
            self.load_schema_tables_privileges()
        return self._stsp_schema_tables_privileges

    def get_schematablesprivilege(self, obj: SchemaTablesPrivilege) -> ObjectState:
        stp = self._stsp_schema_tables_privileges
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

    def load_schema_tables(self):
        #
        # Load schema tables
        #

        self._stsp_schema_tables = collections.defaultdict(
            lambda: collections.defaultdict(dict)
        )

        for datname in self.databases:
            conn = self.get_connection(database=datname)
            raw_rows = conn.execute(f"""
                SELECT schemaname, tablename, tableowner FROM pg_tables
                WHERE schemaname != 'information_schema' AND NOT schemaname LIKE 'pg_%%' 
            """).get_all("schemaname", "tablename", "tableowner")
            for raw in raw_rows:
                self._stsp_schema_tables[datname][raw["schemaname"]][raw["tablename"]] = {
                    "database": datname,
                    "schema": raw["schemaname"],
                    "name": raw["tablename"],
                    "owner": raw["tableowner"],
                }

    def load_schema_tables_privileges(self):
        self._stsp_schema_tables_privileges = collections.defaultdict(
            lambda: collections.defaultdict(
                lambda: collections.defaultdict(
                    lambda: collections.defaultdict(set)
                )
            )
        )

        for datname in self.databases:
            conn = self.get_connection(database=datname)
            #
            # Load schema tables privileges
            #
            raw_rows = conn.execute(f"""
                SELECT
                grantee, table_schema, table_name, STRING_AGG(privilege_type, ',') AS privileges
                FROM information_schema.role_table_grants
                WHERE table_schema != 'information_schema' AND NOT table_schema LIKE 'pg_%%'
                GROUP BY grantee, table_schema, table_name;
            """).get_all("grantee", "table_schema", "table_name", "privileges")
            for raw in raw_rows:
                if not raw["privileges"]:
                    continue
                self._stsp_schema_tables_privileges[datname][raw["table_schema"]][raw["grantee"]][raw["table_name"]] = set(raw["privileges"].split(","))
