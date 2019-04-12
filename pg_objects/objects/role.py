import collections
from typing import List, Generator

from ..graph import Graph
from ..statements import CreateStatement, DropStatement, Statement, TextStatement
from ..utils import get_password_md5
from .base import Object, ObjectLink, SetupAbc, StateProviderAbc, ObjectState


class Role(Object):
    """
    Do not use directly, instead use Group or User.
    """

    FORBIDDEN_ROLES = {"public", "postgres"}

    def _is_managed(self):
        if self.name.lower() in self.FORBIDDEN_ROLES:
            return False
        if self.name.lower().startswith("pg_"):
            return False
        if self.name == self.setup.master_user:
            return False
        return True

    def stmts_to_create(self):
        if not self._is_managed():
            return

        yield CreateStatement(self)

    def stmts_to_drop(self):
        if not self._is_managed():
            return

        # TODO Add "reassign_to" attribute which would be used in these cases
        yield TextStatement(
            query=f"REASSIGN OWNED BY {self.name} TO {self.setup.master_user}",
            database=Statement.ALL_DATABASES,
        )
        yield TextStatement(
            query=f"REVOKE ALL ON SCHEMA public FROM {self.name}",
            database=Statement.ALL_DATABASES
        )
        yield TextStatement(
            query=f"REVOKE ALL ON SCHEMA public FROM {self.name}",
            database=self.setup.master_database,
        )
        yield DropStatement(self)


class Group(Role):
    pass


class User(Role):
    groups: List[str]
    password: str
    inherit: bool

    def __init__(
        self,
        name, password: str = None, groups: List[str] = None, inherit: bool = False,
        present: bool = True, setup: SetupAbc = None,
    ):
        super().__init__(name=name, present=present, setup=setup)
        self.password = password
        self.groups = groups or []
        self.inherit = inherit
        for group in self.groups:
            self.dependencies.add(Group(group))

    def add_to_graph(self, graph: Graph):
        super().add_to_graph(graph)
        for group in self.groups:
            GroupUser(
                group=group, user=self.name,
                present=self.present, setup=self.setup,
            ).add_to_graph(graph)

    def stmts_to_maintain(self) -> Generator[Statement, None, None]:
        inherit_sql = "INHERIT" if self.inherit else "NOINHERIT"
        yield TextStatement(f"""
            ALTER USER {self.name}
            WITH NOCREATEDB
            {inherit_sql}
            {self.get_password_sql()}
        """)

    def get_password_sql(self):
        # If password is not set, the password is not updated and is not disabled either.
        password_sql = "LOGIN"
        if self.password:
            if self.password.startswith("md5"):
                password_hash = self.password
            else:
                password_hash = get_password_md5(username=self.name, password=self.password)
            password_sql = f"LOGIN PASSWORD '{password_hash}'"
        return password_sql


class GroupUser(ObjectLink):
    group: str
    user: str

    def __init__(self, group: str, user: str, present: bool = True, setup: SetupAbc = None):
        super().__init__(present=present, setup=setup)
        self.group = group
        self.user = user
        self.dependencies.add(Group(self.group))
        self.dependencies.add(User(self.user))

    @property
    def key(self):
        return f"{self.__class__.__name__}({self.group}+{self.user})"

    def stmts_to_create(self):
        yield TextStatement(f"ALTER GROUP {self.group} ADD USER {self.user}")

    def stmts_to_drop(self):
        yield TextStatement(f"ALTER GROUP {self.group} DROP USER {self.user}")


class RoleStateProvider(StateProviderAbc):
    _rsp_groups = None
    _rsp_users = None
    _rsp_group_users = None
    _rsp_user_groups = None

    @property
    def groups(self):
        if self._rsp_groups is None:
            self.load_groups_and_users()
        return self._rsp_groups

    @property
    def users(self):
        if self._rsp_users is None:
            self.load_groups_and_users()
        return self._rsp_users

    @property
    def group_users(self):
        if self._rsp_group_users is None:
            self.load_groups_and_users()
        return self._rsp_group_users

    @property
    def user_groups(self):
        if self._rsp_user_groups is None:
            self.load_groups_and_users()
        return self._rsp_user_groups

    def get_user(self, obj: User) -> ObjectState:
        return ObjectState.IS_PRESENT if obj.name in self._rsp_users else ObjectState.IS_ABSENT

    def get_group(self, obj: Group) -> ObjectState:
        return ObjectState.IS_PRESENT if obj.name in self._rsp_groups else ObjectState.IS_ABSENT

    def get_groupuser(self, obj: GroupUser) -> ObjectState:
        return ObjectState.IS_PRESENT if obj.user in self._rsp_group_users[obj.group] else ObjectState.IS_ABSENT

    def load_groups_and_users(self):
        self._rsp_groups = {}
        self._rsp_users = {}
        self._rsp_group_users = collections.defaultdict(list)
        self._rsp_user_groups = collections.defaultdict(list)

        for raw in self.mc.execute("SELECT groname AS name FROM pg_group").get_all("name"):
            if raw["name"].startswith("pg_"):
                continue
            self._rsp_groups[raw["name"]] = raw

        # Always register the public group
        self._rsp_groups["public"] = {"name": "public"}

        for raw in self.mc.execute("SELECT rolname AS name FROM pg_roles").get_all("name"):
            if raw["name"].startswith("pg_") or raw["name"] in self._rsp_groups:
                # pg_roles contains both users and groups so the only way to distinguish
                # them is by checking which ones are not groups.
                continue
            self._rsp_users[raw["name"]] = raw

        raw_rows = self.mc.execute(f"""
            SELECT
            pg_group.groname,
            pg_roles.rolname
            FROM pg_group
            LEFT JOIN pg_roles ON pg_roles.oid = ANY(pg_group.grolist)
            WHERE pg_group.groname NOT LIKE 'pg_%%'
            ORDER BY pg_group.groname, pg_roles.rolname
        """).get_all("groname", "rolname")
        for raw in raw_rows:
            if raw["rolname"]:
                self._rsp_group_users[raw["groname"]].append(raw["rolname"])
                self._rsp_user_groups[raw["rolname"]].append(raw["groname"])
