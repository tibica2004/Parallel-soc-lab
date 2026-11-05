"""
Testele unitare ruleaza fara Elasticsearch si fara model. Modulele creeaza
clientii ES la import, deci le dam valori inofensive inainte de orice import.
Cheia de writer e scoasa: niciun test nu are voie sa scrie in indicii reali.

Faza 22 K: daca `elasticsearch`, `langchain_core`, `langchain_openai` sau `langgraph` lipsesc
din mediu (requirements-test.txt le instaleaza; stub-urile sunt plasa de siguranta), se
inregistreaza in sys.modules stub-uri minimale, suficiente ca modulele sa se IMPORTE. Nu
emuleaza bibliotecile: orice apel real (interogare ES, model) ridica RuntimeError.
"""
import os
import sys
import types
from pathlib import Path

os.environ["ES_URL"] = "http://127.0.0.1:1"
os.environ["ES_API_KEY"] = "test"
os.environ.pop("ES_READONLY_API_KEY", None)
os.environ.pop("ES_WRITER_API_KEY", None)
os.environ.setdefault("OPENAI_API_KEY", "test")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ----------------------------------------------------------------------------------------------
# Stub-uri minimale (doar cand biblioteca lipseste)
# ----------------------------------------------------------------------------------------------

def _missing(name: str) -> bool:
    try:
        __import__(name)
        return False
    except ImportError:
        return True


def _module(name: str, **attrs) -> types.ModuleType:
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    m.__stub__ = True
    sys.modules[name] = m
    return m


def _no_backend(*a, **k):
    raise RuntimeError("stub de test: nu exista backend (Elasticsearch / model) in testele unitare")


class _Stub:
    """Obiect generic: orice atribut e un apel care ridica RuntimeError."""
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        return _no_backend


if _missing("elasticsearch"):
    class ApiError(Exception):
        def __init__(self, message="", meta=None, body=None, *a, **k):
            super().__init__(message)
            self.message, self.meta, self.body = message, meta, body

    class NotFoundError(ApiError):
        pass

    class ConflictError(ApiError):
        pass

    class TransportError(Exception):
        pass

    class Elasticsearch(_Stub):
        pass

    _module("elasticsearch", Elasticsearch=Elasticsearch, ApiError=ApiError, NotFoundError=NotFoundError,
            ConflictError=ConflictError, TransportError=TransportError)


if _missing("langchain_core.messages") or _missing("langchain_core.tools"):
    class BaseMessage:
        def __init__(self, content="", **kw):
            self.content = content
            self.id = kw.pop("id", None)
            self.name = kw.pop("name", None)
            self.tool_calls = kw.pop("tool_calls", [])
            self.additional_kwargs = kw.pop("additional_kwargs", {})
            self.response_metadata = kw.pop("response_metadata", {})
            self.usage_metadata = kw.pop("usage_metadata", None)
            self.__dict__.update(kw)

    class SystemMessage(BaseMessage):
        pass

    class HumanMessage(BaseMessage):
        pass

    class AIMessage(BaseMessage):
        pass

    class ToolMessage(BaseMessage):
        def __init__(self, content="", tool_call_id="", **kw):
            super().__init__(content, **kw)
            self.tool_call_id = tool_call_id

    class _Tool:
        def __init__(self, fn, name=None, description=None):
            self.func, self.name = fn, name or fn.__name__
            self.description = description or (fn.__doc__ or "")

        def invoke(self, args=None, config=None, **kw):
            return self.func(**(args or {}))

        def __call__(self, *a, **k):
            return self.func(*a, **k)

    def tool(fn=None, *a, **k):
        if callable(fn):
            return _Tool(fn)
        return lambda f: _Tool(f, name=fn if isinstance(fn, str) else None)

    class StructuredTool(_Tool):
        @classmethod
        def from_function(cls, func=None, name=None, description=None, **kw):
            return cls(func, name=name, description=description)

    _module("langchain_core")
    _module("langchain_core.messages", BaseMessage=BaseMessage, SystemMessage=SystemMessage,
            HumanMessage=HumanMessage, AIMessage=AIMessage, ToolMessage=ToolMessage, AnyMessage=BaseMessage)
    _module("langchain_core.tools", tool=tool, StructuredTool=StructuredTool, BaseTool=_Tool)


if _missing("langchain_openai"):
    class ChatOpenAI(_Stub):
        def __init__(self, *a, **k):
            self.model_name = k.get("model", "")

        def bind_tools(self, tools, **k):
            return self

        def invoke(self, *a, **k):
            _no_backend()

    _module("langchain_openai", ChatOpenAI=ChatOpenAI)


# un pachet namespace ramas (ex. langgraph/checkpoint dupa un uninstall partial) face
# `import langgraph` sa reuseasca; verificam submodulele folosite efectiv
if _missing("langgraph.graph") or _missing("langgraph.prebuilt"):
    START, END = "__start__", "__end__"

    def add_messages(left, right):
        return list(left or []) + list(right or [])

    class StateGraph:
        def __init__(self, *a, **k):
            self.nodes, self.edges = {}, []

        def add_node(self, name, fn=None, **k):
            self.nodes[name] = fn

        def add_edge(self, a, b):
            self.edges.append((a, b))

        def add_conditional_edges(self, *a, **k):
            pass

        def compile(self, **k):
            return _Stub()

    class ToolNode:
        def __init__(self, tools, **k):
            self.tools = {getattr(t, "name", getattr(t, "__name__", str(t))): t for t in tools}

        def invoke(self, *a, **k):
            _no_backend()

    _module("langgraph")
    _module("langgraph.graph", StateGraph=StateGraph, START=START, END=END)
    _module("langgraph.graph.message", add_messages=add_messages)
    _module("langgraph.prebuilt", ToolNode=ToolNode)


import pytest  # noqa: E402  (dupa stub-uri, dinadins)


@pytest.fixture(autouse=True)
def _fara_retea_la_sanatate(monkeypatch):
    """Verificarea de sanatate a modelului nu are voie sa iasa in retea din teste.
    Implicit: modelul e sanatos. Testele de mod degradat o suprascriu."""
    import degraded
    monkeypatch.setattr(degraded, "llm_healthy", lambda role, fetch=None: True)
