import collections
from typing import Dict

from ..acl_utils import parse_datacl
from ..connection import Connection


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

    def has_database_privilege(self, database, grantee, privilege) -> bool:
        if database in self._dpp_db_privs:
            if grantee in self._dpp_db_privs[database]:
                return privilege in self._dpp_db_privs[database][grantee]
        return False

    # def get_databaseprivilege(self, obj):

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
