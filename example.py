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

setup.group(name="devops", present=False)
setup.group(name="datascience")

setup.user(name="johnny", groups=["datascience"], present=True)
setup.user(name="peter", groups=["datascience"])

setup.database("datascience", owner="datascience", present=True)
setup.database("existingdb", present=False)
setup.schema(database="existingdb", name="existingschema", owner="devops", present=False)
setup.schema(database="datascience", name="private", owner="devops", present=False)

setup.execute()
