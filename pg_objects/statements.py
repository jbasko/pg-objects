from typing import Tuple, ClassVar, List, Union


class Statement:
    query: str
    params: Tuple
    database: str

    # Special value used for Statement.database to mark the statement that
    # it needs to be executed on all managed databases.
    ALL_DATABASES: ClassVar[str] = "ALL_DATABASES"

    def __repr__(self):
        db = ""
        if self.database:
            db = f"{self.database}: "
        return f"<{db}{self.query!r}, {self.params}>"

    @property
    def is_on_all_databases(self):
        """
        Returns True if the statement needs to be executed on all managed databases.
        """
        return self.database == self.ALL_DATABASES


class TransactionOfStatements(Statement):

    statements: List[Statement]

    def __init__(self, *statements, **kwargs):
        self.statements = statements
        self.database = kwargs.pop("database", None)
        assert not kwargs


class TextStatement(Statement):
    def __init__(self, query: str, *params, **kwargs):
        """
        Pass database= when the statement should be executed while connected to a particular database.
        """
        self.query = query
        self.params = params or ()
        self.database = kwargs.pop("database", None)
        assert not kwargs  # "database" is the only supported keyword argument

    def __iter__(self):
        yield self.query
        yield self.params


class CreateStatement(Statement):
    def __init__(self, obj: Union["Database", "Role", "Schema"], *params, **kwargs):
        self.obj = obj
        self.params = params or ()
        self.database = kwargs.pop("database", None)

    @property
    def query(self) -> str:
        return f"CREATE {self.obj.__class__.__name__.upper()} {self.obj.name}"


class DropStatement(Statement):
    def __init__(self, obj: Union["Database", "Role", "Schema"], *params, **kwargs):
        self.obj = obj
        self.params = params or ()
        self.database = kwargs.pop("database", None)

    @property
    def query(self) -> str:
        return f"DROP {self.obj.__class__.__name__.upper()} {self.obj.name}"
