"""
Testele unitare ruleaza fara Elasticsearch si fara model. Modulele creeaza
clientii ES la import, deci le dam valori inofensive inainte de orice import.
Cheia de writer e scoasa: niciun test nu are voie sa scrie in indicii reali.
"""
import os
import sys
from pathlib import Path

os.environ["ES_URL"] = "http://127.0.0.1:1"
os.environ["ES_API_KEY"] = "test"
os.environ.pop("ES_READONLY_API_KEY", None)
os.environ.pop("ES_WRITER_API_KEY", None)
os.environ.setdefault("OPENAI_API_KEY", "test")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
