from llm import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

schema = {
    "type": "object",
    "properties": {
        "classification": {"type": "string", "enum": ["benign","suspicious","malicious","undetermined"]},
        "confidence": {"type": "integer"},
        "reason": {"type": "string"},
    },
    "required": ["classification","confidence","reason"],
}

llm = get_llm("fast", json_schema=schema)
resp = llm.invoke([
    SystemMessage(content="Esti analist de securitate. Clasifica alerta."),
    HumanMessage(content="User tiberiu (admin) a rulat curl catre localhost. Pair in baseline. FP rate 100%."),
])
print("RASPUNS BRUT:")
print(resp.content)
print("\n--- parsabil? ---")
import json
try:
    print(json.loads(resp.content))
    print("DA — guided_json functioneaza")
except Exception as e:
    print(f"NU: {e}")
