import collections
from typing import Dict, Set, Union, Collection

from ..statements import CreateStatement, DropStatement, TextStatement, TransactionOfStatements
from ..acl_utils import parse_datacl
from ..connection import Connection
from ..graph import Graph
from .base import Object, ObjectLink, parse_privileges, SetupAbc, ObjectState


class Database(Object):
    owner: str

    def __init__(self, name, owner: str = None, present: bool = True, setup: SetupAbc = None):
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

        # !!!
        # TODO This could be maintained with an implicit object added to the graph!

        yield TextStatement(f"""
            REVOKE ALL PRIVILEGES
            ON DATABASE {self.name}
            FROM GROUP public
        """)


class DatabaseOwner(ObjectLink):
    database: str
    owner: str

    def __init__(self, database: str, owner: str, present: bool = True, setup: SetupAbc = None):
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


class DatabasePrivilegeStateProvider:

    _dpp_db_privs: Dict
    _dpp_db_privs_lookup = {
        "c": "CONNECT",
        "C": "CREATE",
        "T": "TEMPORARY",
    }

    @property
    def database_privileges(self):
        """
        [datname][grantee] => Set[privilege]
        """
        return self._dpp_db_privs

    def _has_database_privileges(self, database, grantee) -> bool:
        if database in self._dpp_db_privs:
            if grantee in self._dpp_db_privs[database]:
                return True
        return False

    def _get_database_privileges(self, database, grantee) -> Set[str]:
        if database in self._dpp_db_privs:
            if grantee in self._dpp_db_privs[database]:
                return self._dpp_db_privs[database][grantee]
        return set()

    def get_databaseprivilege(self, obj: "DatabasePrivilege") -> ObjectState:
        privileges = self._get_database_privileges(database=obj.database, grantee=obj.grantee)
        if not privileges:
            return ObjectState.IS_ABSENT
        return ObjectState.IS_PRESENT if obj.privileges == privileges else ObjectState.IS_DIFFERENT

    def load_database_privileges(self, mc: Connection):
        self._dpp_db_privs = collections.defaultdict(
            lambda: collections.defaultdict(set)
        )

        for row in mc.execute(f"""
            SELECT datname, datacl FROM pg_database
            WHERE datname NOT LIKE 'template%%'
        """).get_all("datname", "datacl"):
            for (grantee, privs, grantor) in parse_datacl(row["datacl"]):
                self._dpp_db_privs[row["datname"]][grantee].update(
                    self._dpp_db_privs_lookup[p] for p in privs
                )


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
        present: bool = True, setup: SetupAbc = None,
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
