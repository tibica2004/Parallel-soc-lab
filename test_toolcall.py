#!/usr/bin/env python3
"""Verifica un singur lucru: Qwen3 prin Ollama apeleaza o unealta cand i-o legi."""
import os
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from llm import get_llm, NO_THINK


@tool
def get_process_tree(host_name: str, minutes: int = 30) -> dict:
    """Returneaza arborele de procese pentru un host in ultimele N minute.
    Foloseste asta cand vrei sa vezi ce procese au rulat pe un host."""
    # fals — doar verificam ca modelul CERE unealta, nu ca o si executa
    return {"rows": [{"process": "bash", "parent": "sshd"}], "count": 1}


def main():
    llm = get_llm("hunt").bind_tools([get_process_tree])

    msg = [
        SystemMessage(content="Esti un threat hunter. Cand ai nevoie de date, "
                              "APELEAZA uneltele disponibile. Nu inventa date." + NO_THINK),
        HumanMessage(content="Investigheaza hostul web-prod. Ce procese au rulat "
                             "acolo in ultimele 30 de minute?"),
    ]

    print("Trimit cerere care ar trebui sa declanseze un tool call...\n")
    resp = llm.invoke(msg)

    if resp.tool_calls:
        print("SUCCES — modelul a cerut o unealta:")
        for tc in resp.tool_calls:
            print(f"  unealta: {tc['name']}")
            print(f"  argumente: {tc['args']}")
        print("\nTool calling prin Ollama FUNCTIONEAZA. Calea lenta e viabila.")
    else:
        print("PROBLEMA — modelul NU a cerut unealta. A raspuns cu text:")
        print(f"  {resp.content[:400]}")
        print("\nQwen3 prin Ollama nu face tool calling fiabil pe rolul asta.")
        print("Optiuni: vLLM in loc de Ollama, sau alt model.")


if __name__ == "__main__":
    main()
