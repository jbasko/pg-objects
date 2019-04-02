from .connection import get_connection, Connection
from .state_providers.base import DatabasePrivilegeStateProvider


class State(
    DatabasePrivilegeStateProvider
):
    def __init__(self, master_connection: Connection = None):
        self.master_connection: Connection = master_connection

    def load_all(self):
        for k in dir(self):
            if not k.startswith("load_") or k == "load_all":
                continue
            getattr(self, k)(mc=self.master_connection)


if __name__ == "__main__":
    state = State(master_connection=get_connection())
    state.load_all()
