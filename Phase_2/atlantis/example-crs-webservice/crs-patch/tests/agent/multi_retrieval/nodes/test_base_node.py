import pytest
from crete.framework.agent.services.multi_retrieval.nodes.base_node import BaseNode


def test_base_node_instantiation():
    with pytest.raises(TypeError):
        BaseNode()  # pylint: disable=abstract-class-instantiated  # type: ignore


def test_base_node_subclass_call():
    class TestNode(BaseNode):
        def __call__(self, *args, **kwargs):  # type: ignore
            return "called"

    node = TestNode()
    assert node() == "called"
