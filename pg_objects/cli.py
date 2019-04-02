import json
import logging

from aarghparse import cli

from .utils import generate_password, get_password_md5
from .connection import get_connection
from .objects import Setup


log = logging.getLogger(__name__)


@cli
def pg_objects_cli(parser, subcommand):

    parser.add_argument(
        "--env-prefix",
        default="PGO_",
        help="Prefix for environment variables of the connection details",
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
    )

    def setup_from_definition(definition_str: str, args) -> Setup:
        definition = json.loads(definition_str)
        connection = get_connection(env_prefix=args.env_prefix)
        return Setup.from_definition(definition, master_connection=connection)

    def configure_logging(args):
        logging.basicConfig(level=getattr(logging, args.log_level.upper()))

    @subcommand(args=[
        ["definition", {"help": "Definition in JSON"}],
        ["--no-current-state", {"action": "store_true", "help": "Do not load current state"}],
    ])
    def inspect(args):
        """
        Inspect the setup vs the current state.
        """
        configure_logging(args)
        setup = setup_from_definition(definition_str=args.definition, args=args)
        setup.inspect(load_current_state=not args.no_current_state)

    @subcommand(args=[
        ["definition", {"help": "Definition in JSON"}],
        ["--dry-run", {"action": "store_true", "help": "Do not execute any queries, just log what would be done"}],
    ])
    def apply(args):
        """
        Apply the changes necessary to provision the requested setup.
        """
        configure_logging(args)
        setup = setup_from_definition(definition_str=args.definition, args=args)
        setup.execute(dry_run=args.dry_run)

    @subcommand(args=[
        ["username"],
        ["--password", {"help": "Pass a specific password that you want to calculate MD5 for"}]
    ])
    def password(args):
        if args.password:
            password = args.password
        else:
            password = generate_password()
        password_md5 = get_password_md5(username=args.username, password=password)
        print(f"Username: {args.username}\nPassword: {password}\nPassword MD5: {password_md5}")


if __name__ == "__main__":
    pg_objects_cli.run()
