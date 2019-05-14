import functools
from typing import Type, Dict

# Import all types so that we have them in registry

from .objects.base import Object, SetupAbc


@functools.lru_cache(maxsize=1)
def get_types() -> Dict[str, Type[Object]]:
    from .objects.database import Database, DatabasePrivilege
    from .objects.default_privilege import DefaultPrivilege
    from .objects.role import User, Group
    from .objects.schema import SchemaPrivilege, SchemaTablesPrivilege, Schema

    types = {}
    for k, v in locals().items():
        if isinstance(v, type) and issubclass(v, Object):
            types[k] = v
    return types


def deserialise_object(setup: SetupAbc = None, **raw) -> Object:
    obj_type_name = raw.pop("type")
    obj_type = get_types()[obj_type_name]
    return obj_type(**raw, setup=setup)
