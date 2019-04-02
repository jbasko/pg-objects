from .objects.base import ConnectionManager
from .objects.database import DatabasePrivilegeStateProvider
from .objects.schema import SchemaTablesStateProvider
from .connection import Connection, get_connection


class State(
    DatabasePrivilegeStateProvider,
    SchemaTablesStateProvider,
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


if __name__ == "__main__":
    state = State(master_connection=get_connection())
    state.load_all()
