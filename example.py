import logging

from pg_objects.connection import get_connection
from pg_objects.setup import Setup


logging.basicConfig(level=logging.DEBUG)

setup = Setup(master_connection=get_connection())


devops = setup.group(name="devops", present=True)
datascience = setup.group(name="datascience", present=False)

datascience_db = setup.database("datascience", owner=devops.name, present=True)
existingdb = setup.database("existingdb", present=True)

setup.user(name="johnny", password="johnny", groups=["datascience"], present=False)
setup.user(name="peter", password="peter", groups=["devops"], present=True)

setup.schema(database="existingdb", name="existingschema", owner="devops", present=True)
setup.schema(database="datascience", name="private", owner="devops", present=True)

setup.database_privilege(database="existingdb", grantee="datascience", privileges=["CONNECT", "TEMP"], present=False)
setup.database_privilege(database="existingdb", grantee="devops", privileges="ALL", present=True)

setup.schema_privilege(database="existingdb", schema="existingschema", grantee="datascience", privileges="ALL", present=False)

setup.schema_tables_privilege(database="existingdb", schema="existingschema", grantee="datascience", privileges="ALL", present=False)
y = setup.schema_tables_privilege(database="existingdb", schema="existingschema", grantee="devops", privileges="ALL", present=True)
setup.default_privilege(privilege=y, grantor="datascience", present=False)

setup.execute(dry_run=False)
# setup.inspect()
