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

setup.group(name="devops", present=True)
setup.group(name="datascience", present=True)

setup.user(name="johnny", password="johnny", groups=["datascience"], present=True)
setup.user(name="peter", password="peter", groups=["devops"], present=True)

setup.database("datascience", owner="devops", present=True)
setup.database("existingdb", present=True)
setup.schema(database="existingdb", name="existingschema", owner="devops", present=True)
setup.schema(database="datascience", name="private", owner="devops", present=True)

setup.database_privilege(database="existingdb", grantee="datascience", privileges=["CONNECT", "TEMP"], present=True)
setup.database_privilege(database="existingdb", grantee="devops", privileges="ALL", present=True)

setup.schema_privilege(database="existingdb", schema="existingschema", grantee="datascience", privileges="ALL", present=True)

# At first let's support ALL TABLES privilege only.
setup.schema_tables_privilege(database="existingdb", schema="existingschema", grantee="datascience", privileges="ALL", present=True)

setup.execute()

# setup._server_state.pprint()
