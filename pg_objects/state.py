import logging

from .objects.default_privilege import DefaultPrivilege
from .objects.base import ConnectionManager, Object, ObjectState
from .objects.database import DatabasePrivilegeStateProvider, DatabaseStateProvider
from .objects.role import RoleStateProvider
from .objects.schema import SchemaTablesStateProvider, SchemaStateProvider, SchemaTablesPrivilege
from .connection import Connection, get_connection


log = logging.getLogger(__name__)


class State(
    DatabaseStateProvider,
    DatabasePrivilegeStateProvider,
    SchemaStateProvider,
    SchemaTablesStateProvider,
    RoleStateProvider,
):
    def __init__(self, connection_manager: ConnectionManager = None, master_connection: Connection = None):
        if connection_manager:
            self.connection_manager = connection_manager
        else:
            self.connection_manager = ConnectionManager(master_connection=master_connection)

    def load_all(self):
        for k in dir(self):
            if not k.startswith("load_") or k == "load_all":
                continue
            getattr(self, k)()

    def get(self, obj: Object):
        getter = getattr(self, f"get_{obj.__class__.__name__.lower()}", None)
        if getter is None:
            log.warning(f"Requested current state for unsupported object type {obj.__class__}, returning IS_UNKNOWN")
            return ObjectState.IS_UNKNOWN
        return getter(obj)

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


if __name__ == "__main__":
    state = State(master_connection=get_connection())
    state.load_all()
