from openai import OpenAI

client = OpenAI(base_url="http://localhost:8001/v1", api_key="local")

schema = {
    "type": "object",
    "properties": {
        "classification": {"type": "string", "enum": ["benign","suspicious","malicious","undetermined"]},
        "confidence": {"type": "integer"},
        "reason": {"type": "string"},
    },
    "required": ["classification","confidence","reason"],
    "additionalProperties": False,
}

resp = client.chat.completions.create(
    model="foundation-sec",
    messages=[
        {"role": "system", "content": "Esti analist de securitate."},
        {"role": "user", "content": "User tiberiu (admin) a rulat curl catre localhost. Pair in baseline. FP rate 100%. Clasifica."},
    ],
    temperature=0,
    max_tokens=1000,
    extra_body={"guided_json": schema, "guided_decoding_backend": "outlines"},
)
print("RASPUNS:")
print(resp.choices[0].message.content)
import json
try:
    json.loads(resp.choices[0].message.content)
    print("\nDA — JSON valid")
except Exception as e:
    print(f"\nNU: {e}")
