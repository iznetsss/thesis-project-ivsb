import json
from pathlib import Path
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:1234/v1", api_key="sk-lm-7Lo8SOBL:zUDyBTk6zDL2MMPMMxpe")


def analyze_finding(finding):
    """Sends raw code data to the local LLM."""

    user_message = f"""
CWE: {finding['meta']['cwe']}
Semgrep Message: {finding['meta']['message']}
File: {finding['meta']['file_path']}

Imports: 
{finding['global_context']}

Code:
{finding['code_context']}
"""

    try:
        response = client.chat.completions.create(
            model="huihui-qwen3.5-4b-abliterated",
            messages=[
                {"role": "user", "content": user_message}
            ],
            temperature=0.1
        )

        result_text = response.choices[0].message.content
        return json.loads(result_text)

    except json.JSONDecodeError:
        return {"error": "Malformed JSON", "raw": result_text}
    except Exception as e:
        return {"error": str(e)}


def run_audit():
    base_dir = Path(__file__).parent.parent
    input_file = base_dir / "results" / "llm_prompts.json"
    output_file = base_dir / "results" / "audit_results.json"

    with open(input_file, 'r', encoding='utf-8') as f:
        prompts = json.load(f)

    results = []
    total_files = len(prompts)
    print(f"Igniting audit engine... {total_files} anomalies detected.\n")

    for i, finding in enumerate(prompts):
        file_path = finding['meta']['file_path']
        print(f"[{i + 1}/{total_files}] Scrutinizing {file_path}...", end=" ", flush=True)

        llm_verdict = analyze_finding(finding)

        full_result = {
            "file": file_path,
            "cwe": finding['meta']['cwe'],
            "semgrep_message": finding['meta']['message'],
            "llm_analysis": llm_verdict
        }
        results.append(full_result)

        if "error" in llm_verdict:
            print(f"[API ERROR: {llm_verdict['error']}]")
        else:
            v = llm_verdict.get('verdict', 'UNKNOWN')
            print(f"[{v}]")

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)

    print(f"\nAudit sealed. Genesis saved to: {output_file}")


if __name__ == "__main__":
    run_audit()