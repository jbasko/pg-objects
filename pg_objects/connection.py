import logging
import re
import textwrap
from typing import Any, Dict, Generator, Optional

import psycopg2


log = logging.getLogger(__name__)


class Connection:
    KEY_QUERIES = (
        "drop ", "create ", "grant ", "revoke ", "alter ",
    )

    _password_regex = re.compile(r"(password\s+['\"])([^'\"]+)(['\"])", re.IGNORECASE)

    def format_query(self, query: str):
        formatted = " ".join(line.strip() for line in textwrap.dedent(query).splitlines()).strip()
        formatted = self._password_regex.sub(r'\g<1>***\g<3>', formatted)
        return f"{self.database:>15}: {formatted}"

    def log_query(self, query: str):
        check_query = query.strip()[:30].lower()
        if any(keyword in check_query for keyword in self.KEY_QUERIES):
            log.warning(self.format_query(query))
        else:
            log.debug(self.format_query(query))

    def __init__(self, host=None, username=None, password=None, database=None, port=5432, autocommit=True):
        self._connection = None
        self._connection_params = {
            'user': username,
            'password': password,
            'port': int(port),
            'database': database,
            'host': host,
        }
        self._connection_extras = {
            'autocommit': autocommit,
        }

        # Set when establishing connection.
        # Can be used to catch programming errors regardless of the driver being used.
        self.programming_error_cls = None
        self.authentication_error_cls = None

    def clone(self, **kwargs) -> "Connection":
        """
        Create a new connection by replacing just a subset of settings.
        Handy when you need to create a connection using the same credentials
        to a different database.
        """
        kwargs.setdefault('host', self._connection_params['host'])
        kwargs.setdefault('username', self._connection_params['user'])  # username vs user!
        kwargs.setdefault('password', self._connection_params['password'])
        kwargs.setdefault('database', self._connection_params['database'])
        kwargs.setdefault('port', self._connection_params['port'])
        kwargs.setdefault('autocommit', self.autocommit)
        return self.__class__(**kwargs)

    @property
    def connection(self):
        dsn = (
            f"dbname={self.database} "
            f"host={self.host} "
            f"port={self._connection_params['port']} "
            f"user={self.username} "
            f"password={self._connection_params['password']}"
        )
        self._connection = psycopg2.connect(dsn)
        self._connection.autocommit = self._connection_extras['autocommit']
        self.programming_error_cls = psycopg2.ProgrammingError
        self.authentication_error_cls = psycopg2.OperationalError
        return self._connection

    @property
    def autocommit(self):
        return self.connection.autocommit

    @property
    def database(self):
        return self._connection_params["database"]

    @property
    def username(self):
        return self._connection_params["user"]

    @property
    def host(self):
        return self._connection_params['host']

    def __repr__(self):
        return f"{self.__class__.__name__}({self.username}@{self.database}))"

    def __enter__(self):
        # This is not a transaction manager,
        # the main purpose is to close the connection on context exit.
        #
        # For transaction use the context manager returned by begin().
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

    def close(self):
        if self._connection is not None:
            self._connection.commit()
            self._connection.close()
            self._connection = None

    def execute(self, query, *rest) -> "Result":
        query = textwrap.dedent(query)
        cursor = self.connection.cursor()
        try:
            self.log_query(query)
            if rest:
                cursor.execute(query, rest)
            else:
                cursor.execute(query)
        except Exception:
            log.warning(f"Failed to execute query (as {self.username!r}): {self.format_query(query)}")
            raise
        return Result(cursor)

    def statement(self, query, *query_args, columns=None) -> "Statement":
        return Statement(query, *query_args, columns=columns, db=self)

    def begin(self) -> "Transaction":
        return Transaction(self)


class Result:
    def __init__(self, cursor):
        self.cursor = cursor

    def scalar(self) -> Any:
        x, = self.cursor.fetchone()
        return x

    def get_all(self, *columns) -> Generator[Dict, None, None]:
        if len(columns) == 1 and isinstance(columns[0], (list, tuple)):
            columns = columns[0]
        for row in self.cursor.fetchall():
            yield dict(zip(columns, row))

    def get_one(self, *columns) -> Optional[Dict]:
        if len(columns) == 1 and isinstance(columns[0], (list, tuple)):
            columns = columns[0]
        rows = list(self.get_all(columns))
        if len(rows) == 0:
            return None
        if len(rows) > 1:
            raise ValueError(f"Multiple ({len(rows)}) rows returned when one was expected")
        return rows[0]

    @property
    def rowcount(self):
        return self.cursor.rowcount


class Statement(Result):
    def __init__(self, query, *query_args, columns=None, db: "Connection" = None):
        self.db = db
        self.query = query
        self.query_args = query_args
        self.columns = columns
        self._was_executed = False

    def execute(self, tx: "Transaction"=None):
        self._was_executed = True
        if tx is None:
            return self.db.execute(self.query, *self.query_args)
        else:
            tx.execute(self.query, *self.query_args)

    def scalar(self) -> Any:
        self._was_executed = True
        return self.db.execute(self.query, *self.query_args).scalar()

    def get_all(self) -> Generator[Dict, None, None]:
        self._was_executed = True
        assert self.columns
        yield from self.db.execute(self.query, *self.query_args).get_all(self.columns)

    def get_one(self) -> Dict:
        self._was_executed = True
        assert self.columns
        return self.db.execute(self.query, *self.query_args).get_one(self.columns)

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.query!r}>"

    def __del__(self):
        # On tear down warn user if they forgot to execute a statement
        if not self._was_executed:
            log.warning(f"{self} was never executed")


class Transaction:
    def __init__(self, db: Connection):
        self.db = db
        self.cursor = None

    def __enter__(self) -> "Transaction":
        self.cursor = self.db.connection.cursor()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            log.warning(f"Rolling back due to an exception ({exc_type}, {exc_val}, {exc_tb})")
            self.db.connection.rollback()
        else:
            self.db.connection.commit()
        self.cursor.close()

    def execute(self, query, *query_args):
        self.db.log_query(query)
        self.cursor.execute(query, *query_args)
