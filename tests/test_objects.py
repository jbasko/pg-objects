from pg_objects.objects import Setup, ServerState


def test_simple_setup():
    setup = Setup()

    setup.group(name="devops")
    setup.group(name="datascience")

    setup.user(name="johnny", groups=["devops"])
    setup.user(name="peter", groups=["devops", "datascience"])

    setup.database("datascience", owner="datascience")
    setup.schema(database="datascience", name="private", owner="datascience")

    # Fake state
    setup._server_state = ServerState()

    for stmt in setup.generate_stmts():
        print(stmt)
