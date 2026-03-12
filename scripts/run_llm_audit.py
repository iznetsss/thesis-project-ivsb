import json
import csv
import time
import os
from pathlib import Path
from openai import OpenAI

# Initialize client
client = OpenAI(
    base_url="http://127.0.0.1:1234/v1",
    api_key="sk-lm-7Lo8SOBL:zUDyBTk6zDL2MMPMMxpe",
    timeout=600.0
)

def analyze_payload(user_message, max_retries=3):
    messages = [{"role": "user", "content": user_message}]
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model="huihui-qwen3.5-4b-abliterated",
                messages=messages,
                temperature=0.1
            )
            raw_text = response.choices[0].message.content
            try:
                parsed_json = json.loads(raw_text)
            except json.JSONDecodeError:
                parsed_json = {"error": "Malformed JSON", "raw": raw_text}
            return {"parsed": parsed_json, "raw_response": raw_text, "full_prompt": messages}
        except Exception as e:
            err_msg = str(e)
            if "400" in err_msg or "crashed" in err_msg.lower() or "connection" in err_msg.lower():
                print(f"\n[CRITICAL ERROR] Server died: {err_msg}")
                sys.exit(1)
            if attempt < max_retries - 1:
                time.sleep(5)
                continue
            return {"parsed": {"error": err_msg}, "raw_response": err_msg, "full_prompt": messages}

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
            os.fsync(f.fileno()) # Force write to physical drive

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

    output_file = base_dir / "results" / "results_qwen4b_abliterated.json"
    debug_file = base_dir / "results" / "debug_audit_log.json"
    last_item_file = base_dir / "results" / "last_interaction.json" # Special file for easy sharing

    results, debug_logs = load_existing_progress(output_file, debug_file)
    processed_filenames = {res['file'] for res in results}

    with open(prompts_file, 'r', encoding='utf-8') as f:
        prompts_dict = {Path(p['meta']['file_path']).name: p for p in json.load(f)}

    cwe_map = load_cwe_map(csv_file)

    full_queue = []
    for f in tp_dir.glob("*.java"): full_queue.append((f, "TP", "SAST Result Triage"))
    for f in fp_dir.glob("*.java"): full_queue.append((f, "FP", "SAST Result Triage"))
    for f in fn_dir.glob("*.java"): full_queue.append((f, "FN", "Manual Security Review"))

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
        print(f"[{len(results)+1}/{total_all}] [{g_truth}] {filename}...", end=" ", flush=True)

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

        # Save current interaction for quick analysis
        with open(last_item_file, 'w', encoding='utf-8') as f:
            json.dump({"file": filename, "log": resp}, f, indent=4)

        results.append({"file": filename, "ground_truth": g_truth, "cwe": cwe_val, "analysis": resp["parsed"]})
        debug_logs.append({"file": filename, "task": task, "log": resp})
        processed_this_session += 1

        eta = get_eta(start_time, processed_this_session, total_rem - processed_this_session)
        print(f"[{resp['parsed'].get('verdict', 'ERR')}] (ETA: {eta})")

        save_progress(output_file, debug_file, results, debug_logs)

if __name__ == "__main__":
    run_audit()