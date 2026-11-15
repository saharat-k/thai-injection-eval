#!/usr/bin/env python3
"""Verify available 100% free-tier models across Google Gemini API and OpenRouter."""
import json
import os
import urllib.request
from dotenv import load_dotenv

load_dotenv()

def verify_free_models() -> dict:
    results = {"gemini_free": {}, "openrouter_free": []}
    
    # 1. Google Gemini Free-Tier Verification
    gemini_key = os.getenv("GEMINI_API_KEY")
    if gemini_key:
        try:
            from google import genai
            client = genai.Client(api_key=gemini_key)
            live = [m.name for m in client.models.list()]
            for candidate in ["gemini-3.5-flash-lite", "gemini-3.1-flash-lite", "gemini-2.5-flash-lite"]:
                matching = [m for m in live if candidate in m]
                results["gemini_free"][candidate] = matching[0] if matching else None
        except Exception as e:
            results["gemini_error"] = str(e)
    else:
        results["gemini_error"] = "GEMINI_API_KEY not set"

    # 2. OpenRouter 100% Free Models Verification
    openrouter_key = os.getenv("OPENROUTER_API_KEY")
    headers = {"User-Agent": "ThaiInjectionEval/2.0"}
    if openrouter_key:
        headers["Authorization"] = f"Bearer {openrouter_key}"
    try:
        req = urllib.request.Request("https://openrouter.ai/api/v1/models", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            all_models = data.get("data", [])
            # Filter specifically for 100% free models
            free_models = [
                m["id"] for m in all_models
                if m.get("id", "").endswith(":free") or (
                    m.get("pricing", {}).get("prompt") == "0" and m.get("pricing", {}).get("completion") == "0"
                )
            ]
            results["openrouter_free"] = sorted(free_models)
    except Exception as e:
        results["openrouter_error"] = str(e)

    return results

if __name__ == "__main__":
    status = verify_free_models()
    print("=== Google Gemini Free Tier ===")
    for k, v in status.get("gemini_free", {}).items():
        print(f"  {k}: {v or 'NOT AVAILABLE'}")
    if "gemini_error" in status:
        print(f"  [Notice] {status['gemini_error']}")
        
    print("\n=== OpenRouter Free Tier Models (Sample) ===")
    or_free = status.get("openrouter_free", [])
    if or_free:
        for m in or_free[:10]:
            print(f"  - {m}")
        print(f"  ... total {len(or_free)} free models available on OpenRouter")
    elif "openrouter_error" in status:
        print(f"  [Notice] {status['openrouter_error']}")
