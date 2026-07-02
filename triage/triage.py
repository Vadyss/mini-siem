import os
import json
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
model = os.getenv("OPENAI_MODEL")

events_path = Path(__file__).parent / "data" / "events.json"

gpt_resonde = []

with open(events_path) as f:
    events = json.load(f)

system_prompt = """You are a SOC L1 analyst. Analyze the given security event and respond ONLY with a JSON object in this exact format:
{
"summary": "brief human-readable description of what happened",
"severity": "LOW|MED|HIGH|CRITICAL",
"reasoning": "why you assigned this severity",
"recommended_action": "MONITOR|BLOCK_IP|INVESTIGATE|FORCE_PASSWORD_RESET|ESCALATE_INCIDENT"
}
No text outside the JSON."""

for event in events:

    event_clean = {k: v for k, v in event.items() if k not in ("ground_truth_severity", "ground_truth_label")}
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(event, indent=2)}
        ],
        response_format={"type": "json_object"}
    )

    result = json.loads(response.choices[0].message.content)
    print(json.dumps(result, indent=2))
    
    gpt_resonde.append(result)

output_path = Path(__file__).parent / "data" / "results.json"
with open(output_path, "w") as f:
    json.dump(gpt_resonde, f, indent=2)

print(f"Zapsáno {len(gpt_resonde)} výsledků → {output_path}")