"""Tests for the graph model itself, as opposed to how one is built or drawn."""

from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, reciprocal_pairs


def _map(*edges: GraphEdge) -> ActivityGraph:
    return ActivityGraph(kind=GraphKind.BEHAVIOUR, client_ip="203.0.113.5", edges=edges)


def test_a_pair_joined_both_ways_is_reciprocal() -> None:
    graph = _map(GraphEdge("a", "b"), GraphEdge("b", "a"))

    assert reciprocal_pairs(graph) == {frozenset({"a", "b"})}


def test_an_edge_with_no_counterpart_is_not() -> None:
    graph = _map(GraphEdge("a", "b"), GraphEdge("b", "c"))

    assert reciprocal_pairs(graph) == frozenset()


def test_a_loop_is_not_a_pair() -> None:
    """`a -> a` satisfies "there is an edge each way" read literally, and a
    renderer that separated it would move a self-loop off the node it loops on."""
    graph = _map(GraphEdge("a", "a"))

    assert reciprocal_pairs(graph) == frozenset()


def test_a_pair_is_named_once_however_the_edges_are_ordered() -> None:
    """The answer is about a pair of nodes, not about a pair of edges: a
    renderer asks it once per edge and must get the same answer both times."""
    one = _map(GraphEdge("a", "b"), GraphEdge("b", "a"))
    other = _map(GraphEdge("b", "a"), GraphEdge("a", "b"))

    assert reciprocal_pairs(one) == reciprocal_pairs(other)
    assert len(reciprocal_pairs(one)) == 1


def test_a_graph_with_no_edges_names_no_pairs() -> None:
    assert reciprocal_pairs(_map()) == frozenset()
