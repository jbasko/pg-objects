from typing import Set, Union, Collection

from ..graph import Graph
from ..statements import CreateStatement, DropStatement, TextStatement, TransactionOfStatements
from .base import Object, SetupAbc, ObjectLink, parse_privileges
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
