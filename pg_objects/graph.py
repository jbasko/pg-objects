import collections
from typing import Iterable, Union, Hashable


class Vertex:
    def __init__(self, value, graph: "Graph"):
        self._graph = graph
        self.value = value

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        return isinstance(self, type(other)) and self.value == other.value

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.value!r}>"

    def add_dependency(self, dependency: "Vertex"):
        self._graph.add_edge(self, dependency)

    @property
    def dependencies(self):
        return self._graph._edges_from[self]

    @property
    def dependants(self):
        return self._graph._edges_to[self]


class Graph:
    def __init__(self):
        self._vertices = dict()
        self._edges_to = collections.defaultdict(set)
        self._edges_from = collections.defaultdict(set)

    def new_vertex(self, value):
        node = Vertex(value, graph=self)
        self._vertices[hash(value)] = node
        return node

    def add_edge(self, vertex_from: Union[Vertex, Hashable], vertex_to: Union[Vertex, Hashable]):
        if not isinstance(vertex_from, Vertex):
            vertex_from = self._vertices[hash(vertex_from)]
        if not isinstance(vertex_to, Vertex):
            vertex_to = self._vertices[hash(vertex_to)]
        self._edges_from[vertex_from].add(vertex_to)
        self._edges_to[vertex_to].add(vertex_from)

    def remove_edge(self, vertex_from: Vertex, vertex_to: Vertex):
        self._edges_from[vertex_from].remove(vertex_to)
        self._edges_to[vertex_to].remove(vertex_from)

    def __iter__(self) -> Iterable[Vertex]:
        return iter(self._vertices.values())

    def __getitem__(self, value):
        return self._vertices[hash(value)]

    def __contains__(self, value):
        return hash(value) in self._vertices

    def __repr__(self):
        return f"<{self.__class__.__name__} {set(self._vertices.values())}>"

    def clone(self) -> "Graph":
        g = Graph()

        for v in self._vertices.values():
            g.new_vertex(v.value)

        for vertex_from, vertices_to in self._edges_from.items():
            for vertex_to in vertices_to:
                g.add_edge(g[vertex_from.value], g[vertex_to.value])

        return g

    def has_edges(self):
        return sum(len(vertices_to) for _, vertices_to in self._edges_from.items()) > 0

    @classmethod
    def from_edge_list(cls, *edge_list):
        g = cls()
        for (vertex_from, vertex_to) in edge_list:
            if vertex_from not in g:
                g.new_vertex(vertex_from)
            if vertex_to not in g:
                g.new_vertex(vertex_to)
            g.add_edge(g[vertex_from], g[vertex_to])
        return g

    def topological_sort_by_kahn(self):
        # https://en.wikipedia.org/wiki/Topological_sorting
        G: Graph = self.clone()
        L = []
        S = set(v for v in G if not v.dependencies)

        if not S:
            raise ValueError("Graph has no vertex with no incoming edges")

        while S:
            n = S.pop()
            L.append(n)

            for m in set(n.dependants):
                G.remove_edge(m, n)
                if not m.dependencies:
                    S.add(m)

        if G.has_edges():
            raise ValueError("Graph has at least one cycle")

        # Return the vertices of the original graph, not the clone
        return [self[v.value] for v in L]


def graph_definition_example1():
    graph = Graph()
    a = graph.new_vertex("a")
    b = graph.new_vertex("b")
    c = graph.new_vertex("c")
    d = graph.new_vertex("d")
    e = graph.new_vertex("e")
    a.add_dependency(b)
    c.add_dependency(b)
    d.add_dependency(a)
    e.add_dependency(c)
    return graph


def graph_definition_example2():
    return Graph.from_edge_list(("a", "b"), ("c", "b"), ("d", "a"), ("e", "c"))


def topological_sort_example():
    g1 = graph_definition_example1()
    print(g1)
    print(topological_sort_by_kahn(g1))

    g2 = graph_definition_example2()
    print(g2)
    print(topological_sort_by_kahn(g2))


if __name__ == "__main__":
    topological_sort_example()
