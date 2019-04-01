import logging
import os

logging.basicConfig(level=logging.DEBUG)

from pg_objects.connection import Connection
from pg_objects.objects import Setup

setup = Setup(master_connection=Connection(
    host=os.environ.get("PGO_HOST", "localhost"),
    port=os.environ.get("PGO_PORT", "5432"),
    username=os.environ["PGO_USERNAME"],
    password=os.environ.get("PGO_PASSWORD", ""),
    database=os.environ.get("PGO_DATABASE", "postgres")),
)


devops = setup.group(name="devops", present=True)
datascience = setup.group(name="datascience", present=False)

datascience_db = setup.database("datascience", owner=devops.name, present=True)
existingdb = setup.database("existingdb", present=True)

setup.user(name="johnny", password="johnny", groups=["datascience"], databases=["existingdb"], present=False)
setup.user(name="peter", password="peter", groups=["devops"], databases=["existingdb"], present=True)

setup.schema(database="existingdb", name="existingschema", owner="devops", present=True)
setup.schema(database="datascience", name="private", owner="devops", present=True)

setup.database_privilege(database="existingdb", grantee="datascience", privileges=["CONNECT", "TEMP"], present=False)
setup.database_privilege(database="existingdb", grantee="devops", privileges="ALL", present=True)

setup.schema_privilege(database="existingdb", schema="existingschema", grantee="datascience", privileges="ALL", present=False)

setup.schema_tables_privilege(database="existingdb", schema="existingschema", grantee="datascience", privileges="ALL", present=False)
y = setup.schema_tables_privilege(database="existingdb", schema="existingschema", grantee="devops", privileges="ALL", present=True)
setup.default_privilege(privilege=y, grantor="datascience", present=False)

setup.execute(dry_run=True)
# setup.inspect()
