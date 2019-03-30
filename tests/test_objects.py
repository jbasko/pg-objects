from pg_objects.objects import Setup


def test_simple_setup():
    setup = Setup()

    setup.group(name="devops")
    setup.group(name="datascience")

    setup.user(name="johnny", groups=["devops"])
    setup.user(name="peter", groups=["devops", "datascience"])

    setup.database("datascience", owner="datascience")
    setup.schema(database="datascience", name="private", owner="datascience")

    graph = setup.generate_graph()
    print(graph)

    for i, v in enumerate(graph.topological_sort_by_kahn()):
        print(i, v.value)

    print("--")

    for i, v in enumerate(reversed(graph.topological_sort_by_kahn())):
        print(i, v.value)
