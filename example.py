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
setup.group(name="datascience", present=False)

setup.user(name="johnny", password="johnny", groups=["datascience"], present=False)
setup.user(name="peter", password="peter", groups=["devops"])

setup.database("datascience", owner="devops", present=True)
setup.database("existingdb", present=True)
setup.schema(database="existingdb", name="existingschema", owner="devops", present=True)
setup.schema(database="datascience", name="private", owner="devops", present=True)

setup.database_privilege("existingdb", group="datascience", privileges="ALL", present=False)

setup.execute()
