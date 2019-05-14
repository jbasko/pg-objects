from unittest import mock

from pg_objects.objects.database import DatabasePrivilege
from pg_objects.setup import Setup


def test_simple_setup():
    setup = Setup(master_connection=mock.Mock())

    setup.group(name="devops")
    setup.group(name="datascience")

    setup.user(name="johnny", groups=["devops"])
    setup.user(name="peter", groups=["devops", "datascience"])

    setup.database("datascience", owner="datascience")
    setup.schema(database="datascience", name="private", owner="datascience")


def test_database_privilege():
    dp = DatabasePrivilege("db", "rol", privileges="ALL")
    assert dp.privileges == DatabasePrivilege.ALL == {"CONNECT", "CREATE", "TEMPORARY"}

    dp = DatabasePrivilege("db", "rol", privileges="CONNECT")
    assert dp.privileges == {"CONNECT"}

    dp = DatabasePrivilege("db", "rol", privileges=["CONNECT", "TEMPORARY"])
    assert dp.privileges == {"CONNECT", "TEMPORARY"}

    dp = DatabasePrivilege("db", "rol", privileges=["CONNECT", "TEMP"])
    assert dp.privileges == {"CONNECT", "TEMPORARY"}
