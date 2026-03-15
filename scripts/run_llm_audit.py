import json
import csv
import time
import os
import sys
import anthropic
import re
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

# ==========================================
# API KEYS CONFIGURATION
# ==========================================
load_dotenv()

LOCAL_API_KEY = os.getenv("LOCAL_API_KEY", "default_local_key")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# Global vars set by interactive menu
CLIENT = None
CONFIG = {}

# === SYSTEM CONFIGURATION START ===
SYSTEM_PROMPT = """Role: You are an expert DevSecOps AI Security Auditor integrated into a Secure Software Development Life Cycle (S-SDLC). 
Your objective is to perform an independent technical analysis of Java source code to ensure high software assurance.

Operational Context:
You act as a Tier-2 Security Analyst. Your goal is to minimize both "Alert Fatigue" (by aggressively filtering noise) and "Security Gaps" (by identifying complex flaws).

Core Directives for Analysis:
1. Zero Trust for Automated Scanners: SAST tools lack context and generate high rates of False Positives. Maintain strict engineering skepticism. Do not blindly trust the provided alert.
2. Evidence-Based Verdicts: To classify an alert as a "True Positive", you MUST trace an unbroken, unsanitized path from user-controlled input to a vulnerable sink. 
3. False Positive Identification: If the variable reaching the sink is a hardcoded constant, is neutralized by a sanitization library, or is strictly validated by conditional logic before use, you MUST output "False Positive".

Task Scenarios:
1. SAST Result Triage (Context: Automated Alert Provided): 
   Critically evaluate the SAST alert against the actual data flow. Prove or disprove the scanner's claim based on the Core Directives.
2. Manual Security Review (Context: No Prior Alerts): 
   Perform a comprehensive analysis of the code. Focus on logic flaws and complex injection vectors that signature-based tools overlook.

Output Requirement: 
Return ONLY a valid JSON object. Do not include prose or markdown formatting outside the JSON."""

JSON_SCHEMA = {
    "name": "security_audit_response",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["True Positive", "False Positive"]
            },
            "confidence_score": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10
            },
            "risk_domain": {
                "type": "string",
                "description": "CWE category or vulnerability type (e.g. SQL Injection, XSS, Path Traversal)"
            },
            "technical_justification": {
                "type": "string",
                "description": "Detailed engineering analysis of the data flow and sinks."
            },
            "remediation_advice": {
                "type": "string",
                "description": "Actionable steps to fix the issue or improve code quality."
            }
        },
        "required": ["verdict", "confidence_score", "risk_domain", "technical_justification", "remediation_advice"],
        "additionalProperties": False
    }
}


# === SYSTEM CONFIGURATION END ===

def setup_environment():
    global CLIENT, CONFIG

    print("\n=== DevSecOps AI Auditor Setup ===")
    print("Select execution mode:")
    print("1. Local")
    print("2. Cloud")
    mode_choice = input("Enter 1 or 2: ").strip()

    if mode_choice == '1':
        CONFIG['mode'] = 'local'
        CONFIG['provider'] = 'local'
        print("\nSelect Local Model:")
        print("1. huihui-qwen3.5-4b-abliterated")
        print("2. qwen3.5-4b")
        print("3. gemma-3-4b-it")
        model_choice = input("Enter 1, 2, or 3: ").strip()
        models_map = {"1": "huihui-qwen3.5-4b-abliterated", "2": "qwen3.5-4b", "3": "gemma-3-4b-it"}
        CONFIG['model'] = models_map.get(model_choice, "qwen3.5-4b")

        CLIENT = OpenAI(
            base_url="http://127.0.0.1:1234/v1",
            api_key=LOCAL_API_KEY,
            timeout=600.0
        )
    else:
        CONFIG['mode'] = 'cloud'
        print("\nSelect Cloud Provider:")
        print("1. OpenAI (gpt-5-nano-2025-08-07)")
        print("2. Claude (claude-opus-4-6)")
        provider_choice = input("Enter 1 or 2: ").strip()

        if provider_choice == '1':
            CONFIG['provider'] = 'openai'
            CONFIG['model'] = 'gpt-5-nano-2025-08-07'
            CLIENT = OpenAI(api_key=OPENAI_API_KEY, timeout=600.0)
        else:
            CONFIG['provider'] = 'claude'
            CONFIG['model'] = 'claude-opus-4-6'

    print(f"\n[INFO] Starting audit with model: {CONFIG['model']} ({CONFIG['mode'].upper()})\n")


def analyze_payload(user_message, max_retries=3):
    # Enforce strict flat JSON for Claude
    claude_system_prompt = SYSTEM_PROMPT + (
        "\n\nCRITICAL INSTRUCTION: Your output MUST be a flat JSON object with EXACTLY these top-level keys. "
        "Do NOT nest them under an 'analysis' key:\n"
        "- verdict (String: 'True Positive' or 'False Positive')\n"
        "- confidence_score (Integer: 1-10)\n"
        "- risk_domain (String)\n"
        "- technical_justification (String)\n"
        "- remediation_advice (String)"
    )

    if CONFIG['mode'] == 'cloud':
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message}
        ]
    else:
        messages = [{"role": "user", "content": user_message}]

    for attempt in range(max_retries):
        try:
            kwargs = {
                "model": CONFIG['model'],
                "messages": messages,
                "temperature": 1.0 if CONFIG['mode'] == 'cloud' else 0.1
            }

            if CONFIG['provider'] == 'claude':
                # Use the heavily enforced system prompt for Claude
                anthro_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
                response = anthro_client.messages.create(
                    model=CONFIG['model'],
                    system=claude_system_prompt,
                    messages=[{"role": "user", "content": user_message}],
                    temperature=1.0,
                    max_tokens=8192
                )
                raw_text = response.content[0].text

            else:
                if CONFIG['mode'] == 'local':
                    kwargs["top_p"] = 0.1
                    kwargs["max_tokens"] = 12288
                    kwargs["extra_body"] = {"top_k": 20, "repeat_penalty": 1.1, "min_p": 0.05}
                elif CONFIG['provider'] == 'openai':
                    kwargs["max_completion_tokens"] = 12288
                    kwargs["response_format"] = {"type": "json_schema", "json_schema": JSON_SCHEMA}

                response = CLIENT.chat.completions.create(**kwargs)
                raw_text = response.choices[0].message.content

            # SMARTER JSON EXTRACTION (Handles Claude's markdown and weird formatting)
            clean_text = raw_text.strip()
            # Find everything between the first { and the last }
            match = re.search(r'\{.*\}', clean_text, re.DOTALL)
            if match:
                clean_text = match.group(0)

            # JSON parsing
            try:
                parsed_json = json.loads(clean_text)

                # Failsafe: If Claude STILL nested it under "analysis", pull it up
                if "analysis" in parsed_json and "verdict" not in parsed_json:
                    parsed_json = parsed_json["analysis"]

            except json.JSONDecodeError:
                parsed_json = {"error": "Malformed JSON", "raw": raw_text}

            return {"parsed": parsed_json, "raw_response": raw_text, "full_prompt": messages}

        except Exception as e:
            err_msg = str(e)

            if "429" in err_msg and CONFIG['mode'] == 'cloud':
                wait_time = 20 * (attempt + 1)
                print(f"\n[RATE LIMIT] Waiting {wait_time}s...")
                time.sleep(wait_time)
                continue

            if "400" in err_msg or "crashed" in err_msg.lower() or "connection" in err_msg.lower():
                print(f"\n[CRITICAL ERROR] Server died: {err_msg}")
                sys.exit(1)

            if attempt < max_retries - 1:
                time.sleep(5)
                continue
            return {"parsed": {"error": err_msg}, "raw_response": err_msg, "full_prompt": messages}
    return None


def load_existing_progress(output_file, debug_file):
    results, debug_logs = [], []
    if output_file.exists():
        with open(output_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
    if debug_file.exists():
        with open(debug_file, 'r', encoding='utf-8') as f:
            debug_logs = json.load(f)
    return results, debug_logs


def save_progress(output_file, debug_file, results, debug_logs):
    """Saves progress and forces OS to write to disk immediately."""
    for path, data in [(output_file, results), (debug_file, debug_logs)]:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
            f.flush()
            os.fsync(f.fileno())


def load_cwe_map(csv_path):
    cwe_map = {}
    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            t_name = row.get('testName') or row.get('testname') or list(row.values())[0]
            cwe = row.get('cwe') or list(row.values())[3]
            if t_name: cwe_map[f"{t_name.strip()}.java"] = cwe.strip()
    return cwe_map


def parse_java(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    imports = "".join([l for l in lines if l.startswith("import ")])
    code = "".join([l for l in lines if not l.startswith("import ")])
    return imports, code


def get_eta(start_time, processed_this_session, total_remaining):
    if processed_this_session == 0: return "Calculating..."
    elapsed = time.time() - start_time
    avg_time = elapsed / processed_this_session
    eta_sec = int(avg_time * total_remaining)
    h, rem = divmod(eta_sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s" if h > 0 else f"{m:02d}m {s:02d}s"


def run_audit():
    base_dir = Path(__file__).parent.parent
    prompts_file = base_dir / "results" / "llm_prompts.json"
    csv_file = base_dir / "data" / "expectedresults_full.csv"

    tp_dir = base_dir / "data" / "benchmark_source" / "research_files" / "sast_alerts" / "true_positives"
    fp_dir = base_dir / "data" / "benchmark_source" / "research_files" / "sast_alerts" / "false_positives"
    fn_dir = base_dir / "data" / "benchmark_source" / "research_files" / "blind_test" / "false_negatives"

    # Dynamic file naming based on model
    safe_model_name = CONFIG['model'].replace('-', '_').replace('.', '_')
    out_dir = base_dir / "results" / "models_results"
    out_dir.mkdir(parents=True, exist_ok=True)

    output_file = out_dir / f"audit_results_{safe_model_name}.json"
    debug_file = out_dir / f"debug_log_{safe_model_name}.json"
    last_item_file = out_dir / f"last_interaction_{safe_model_name}.json"

    results, debug_logs = load_existing_progress(output_file, debug_file)
    processed_filenames = {res['file'] for res in results}

    with open(prompts_file, 'r', encoding='utf-8') as f:
        prompts_dict = {Path(p['meta']['file_path']).name: p for p in json.load(f)}

    cwe_map = load_cwe_map(csv_file)

    full_queue = []
    for f in tp_dir.glob("*.java"): full_queue.append((f, "TP", "SAST Result Triage"))
    for f in fp_dir.glob("*.java"): full_queue.append((f, "FP", "SAST Result Triage"))
    for f in fn_dir.glob("*.java"): full_queue.append((f, "FN", "Manual Security Review"))

    # Filter queue if running Claude (only run the 200 selected files)
    if CONFIG.get('provider') == 'claude':
        opus_queue_path = base_dir / "results" / "opus_queue_200.json"
        if opus_queue_path.exists():
            with open(opus_queue_path, 'r', encoding='utf-8') as f:
                target_files = set(json.load(f))
            full_queue = [item for item in full_queue if item[0].name in target_files]
            print(f"[INFO] Claude mode active: filtering to {len(full_queue)} files from opus_queue_200.json")
        else:
            print("[WARN] opus_queue_200.json not found! Running full queue.")

    remaining_queue = [item for item in full_queue if item[0].name not in processed_filenames]
    total_all, total_rem = len(full_queue), len(remaining_queue)

    if total_rem == 0:
        print("Audit complete.")
        return

    print(f"Resuming: {len(processed_filenames)} done, {total_rem} left.\n")

    start_time = time.time()
    processed_this_session = 0

    for f_path, g_truth, task in remaining_queue:
        filename = f_path.name
        print(f"[{len(results) + 1}/{total_all}] [{g_truth}] {filename}...", end=" ", flush=True)

        if task == "SAST Result Triage":
            fnd = prompts_dict.get(filename)
            if fnd:
                user_msg = f"Context: {task}\nCWE: {fnd['meta']['cwe']}\nSAST Alert: {fnd['meta']['message']}\nFile: {filename}\nImports:\n{fnd['global_context']}\nCode:\n{fnd['code_context']}"
                cwe_val = fnd['meta']['cwe']
            else:
                imp, code = parse_java(f_path)
                cwe_val = cwe_map.get(filename, "Unknown")
                user_msg = f"Context: {task}\nCWE: {cwe_val}\nFile: {filename}\nCode:\n{code}"
        else:
            imp, code = parse_java(f_path)
            cwe_val = cwe_map.get(filename, "Unknown")
            user_msg = f"Context: {task}\nTarget Category: CWE-{cwe_val}\nFile: {filename}\nCode:\n{code}"

        resp = analyze_payload(user_msg)

        if resp:  # Ensure response exists
            with open(last_item_file, 'w', encoding='utf-8') as f:
                json.dump({"file": filename, "log": resp}, f, indent=4)

            results.append({"file": filename, "ground_truth": g_truth, "cwe": cwe_val, "analysis": resp["parsed"]})
            debug_logs.append({"file": filename, "task": task, "log": resp})

        processed_this_session += 1

        eta = get_eta(start_time, processed_this_session, total_rem - processed_this_session)

        # Safe dictionary access in case of malformed JSON
        verdict = resp.get('parsed', {}).get('verdict', 'ERR') if resp else 'ERR'
        print(f"[{verdict}] (ETA: {eta})")

        save_progress(output_file, debug_file, results, debug_logs)

        # Rate limit protection for cloud
        if CONFIG['mode'] == 'cloud':
            time.sleep(0.75)


if __name__ == "__main__":
    setup_environment()
    run_audit()