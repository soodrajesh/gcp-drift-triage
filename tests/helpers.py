import json
from importlib import resources

from driftriage.llm import LLM, LLMResult


def sample(name: str) -> dict:
    return json.loads((resources.files("driftriage") / "samples" / f"{name}.json").read_text())


def rd(rtype, name, before, after, actions=("update",)):
    return {
        "address": f"{rtype}.{name}",
        "type": rtype,
        "name": name,
        "change": {"actions": list(actions), "before": before, "after": after},
    }


def plan(*drifts):
    return {"resource_drift": list(drifts)}


class ScriptedLLM(LLM):
    name, model = "scripted", "scripted-1"

    def __init__(self, reply=None, *, raises=None, delay=0.0):
        self.reply, self.raises, self.delay, self.calls = reply, raises, delay, 0

    async def complete_json(self, system, user, max_tokens=1200):
        import asyncio

        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.raises:
            raise self.raises
        r = self.reply(json.loads(user)) if callable(self.reply) else self.reply
        return LLMResult(r if isinstance(r, str) else json.dumps(r), 100, 50, 0.001)
