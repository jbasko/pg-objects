"""
The best documentation on ACL parsing is at
https://docs.aws.amazon.com/redshift/latest/dg/r_PG_DEFAULT_ACL.html
"""

import collections
import shlex
from typing import List

node = collections.namedtuple("node", field_names=["parent", "stack"])


def _parse_acl_list_str(array_str) -> List[str]:
    """
    Parses the string representation of pg_default_acl.defaclacl into a list
    of strings.
    """
    if array_str is None:
        return []

    current = None
    tokenizer = shlex.shlex(array_str)
    tokenizer.whitespace = ","
    tokenizer.wordchars += " =/"
    for token in tokenizer:
        if token == "{":
            current = node(current, [])
        elif token == "}":
            if not current.parent:
                return current.stack
            else:
                current.parent.stack.append(current.stack)
                current = current.parent
        else:
            if token and token[0] == token[-1] == '"':
                token = token[1:-1]
            if token:
                current.stack.append(token)
    return current


def parse_datacl(datacl: str):
    """
    Returns a list of tuples of (grantee, privs_str, grantor)
    where privs_str is a string that can contain:
        C - for CREATE privilege
        c - for CONNECT privilege
        T - for TEMPORARY (alias TEMP) privilege
    """
    privs = []
    for raw in _parse_acl_list_str(datacl):
        grantee, privs_and_grantor = raw.split("=")
        if grantee == "":
            grantee = "public"
        privs_str, grantor = privs_and_grantor.split("/")
        privs.append((grantee, privs_str, grantor))
    return privs
