from openai import OpenAI
import hashlib

client = OpenAI()

# simple cache.. this cache resets when server restarts, but yeah kinda good enough for now ib.. maybe redis ?
LLM_CACHE = {}


def generate_cache_key(event):
    # create unique key based on important fields
    key_string = f"{event['attack_type']}|{event['timeline']}|{event['reasons']}"
    return hashlib.md5(key_string.encode()).hexdigest()



def generate_llm_explanation(event):
    cache_key = generate_cache_key(event)

    if cache_key in LLM_CACHE:
        return LLM_CACHE[cache_key]

    prompt = f"""
You are a cybersecurity analyst.

User: {event['user']}
Detected Attack: {event['attack_type']}
Alert Type: {event.get('alert_type', 'unknown')}

Timeline:
{chr(10).join(event['timeline'])}

Reasons:
{", ".join(event['reasons'])}

Explain:
1. What happened
2. Why it is suspicious
3. Possible impact

Keep it concise and professional.
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )

        explanation = response.choices[0].message.content
        LLM_CACHE[cache_key] = explanation

        return explanation

    except Exception as e:
        return f"LLM failed: {str(e)}"