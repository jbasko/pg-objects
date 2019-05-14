from typing import Set, ClassVar

from ..statements import TextStatement, TransactionOfStatements
from .base import Object, SetupAbc


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

    def __init__(self, privilege: DefaultPrivilegeReady, grantor: str, present: bool = True, setup: SetupAbc = None):
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
