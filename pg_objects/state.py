from .objects.database import DatabasePrivilegeStateProvider
from .connection import get_connection, Connection


class State(
    DatabasePrivilegeStateProvider
):
    def __init__(self, master_connection: Connection = None):
        if master_connection is None:
            master_connection = get_connection()
        self.master_connection: Connection = master_connection

    def load_all(self):
        for k in dir(self):
            if not k.startswith("load_") or k == "load_all":
                continue
            getattr(self, k)(mc=self.master_connection)


if __name__ == "__main__":
    state = State()
    state.load_all()
