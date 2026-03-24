# Extracts method-level semantic context and imports from Java files to build a structured dataset for LLM prompting.
import json
import re
from pathlib import Path

def get_global_header(lines):
    """Extracts package and import statements from the top of the file."""
    header = []
    for line in lines[:50]:
        stripped = line.strip()
        if stripped.startswith("package ") or stripped.startswith("import "):
            header.append(stripped)
        elif "class " in line or "interface " in line:
            break
    return "\n".join(header)

def find_method_boundaries(lines, target_idx):
    """Finds start and end line indices for the method containing the target."""
    start_idx = 0
    # Upward Search (Method Start)
    for i in range(target_idx, -1, -1):
        if re.search(r'\b(public|private|protected)\b.*\(', lines[i]):
            start_idx = i
            break

    # Downward Search (Method End)
    end_idx = len(lines) - 1
    brace_count = 0
    found_first_brace = False

    for i in range(start_idx, len(lines)):
        brace_count += lines[i].count('{')
        brace_count -= lines[i].count('}')
        if '{' in lines[i]:
            found_first_brace = True
        if found_first_brace and brace_count == 0:
            end_idx = i
            break

    return start_idx, end_idx

def extract_semantic_context(lines, start_idx, end_idx, target_idx):
    """Extracts the method body based on length constraints."""
    method_length = end_idx - start_idx + 1

    if method_length <= 100:
        return [(i + 1, lines[i].rstrip()) for i in range(start_idx, end_idx + 1)]
    else:
        result = []
        head_end = min(start_idx + 10, end_idx)
        for i in range(start_idx, head_end + 1):
            result.append((i + 1, lines[i].rstrip()))

        result.append((None, "// ... [code skipped] ..."))

        win_start = max(head_end + 1, target_idx - 50)
        win_end = min(end_idx - 1, target_idx + 50)
        for i in range(win_start, win_end + 1):
            result.append((i + 1, lines[i].rstrip()))

        if win_end < end_idx - 1:
            result.append((None, "// ... [code skipped] ..."))

        result.append((end_idx + 1, lines[end_idx].rstrip()))
        return result

def format_code_block(context_lines, target_line):
    """Formats context into Markdown with vulnerability marker."""
    formatted = ["```java"]
    for line_num, text in context_lines:
        if line_num is None:
            formatted.append(text)
        else:
            prefix = ">> " if line_num == target_line else "   "
            formatted.append(f"{prefix}{line_num}: {text}")
    formatted.append("```")
    return "\n".join(formatted)

def build_llm_dataset():
    base_dir = Path(__file__).parent.parent
    input_file = base_dir / "results" / "initial_scan.json"
    output_file = base_dir / "results" / "llm_prompts.json"

    # Define new target directories where files were moved
    tp_dir = base_dir / "data" / "benchmark_source" / "research_files" / "sast_alerts" / "true_positives"
    fp_dir = base_dir / "data" / "benchmark_source" / "research_files" / "sast_alerts" / "false_positives"

    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    findings = data.get("results", [])
    processed_data = []
    processed_files = set() # Prevent duplicate alerts for the same file

    print("Parsing Java files from SAST alert directories...")

    for item in findings:
        filename = Path(item["path"]).name

        if filename in processed_files:
            continue

        # Look for the file in our sorted TP and FP directories
        abs_file_path = tp_dir / filename
        if not abs_file_path.exists():
            abs_file_path = fp_dir / filename
            if not abs_file_path.exists():
                continue # File is likely a True Negative in archive, skip it

        target_line = item["start"]["line"]
        target_idx = target_line - 1

        with open(abs_file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        global_context = get_global_header(lines)
        start_idx, end_idx = find_method_boundaries(lines, target_idx)
        context_lines = extract_semantic_context(lines, start_idx, end_idx, target_idx)
        code_context = format_code_block(context_lines, target_line)

        cwe_list = item["extra"]["metadata"].get("cwe", ["Unknown"])
        cwe_string = cwe_list[0] if cwe_list else "Unknown"

        finding_info = {
            "meta": {
                "cwe": cwe_string,
                "message": item["extra"]["message"],
                "file_path": str(abs_file_path)
            },
            "global_context": global_context,
            "code_context": code_context
        }

        processed_data.append(finding_info)
        processed_files.add(filename)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(processed_data, f, indent=4)

    print(f"Success! Extracted context for {len(processed_data)} SAST alerts.")
    print(f"Saved dataset to: {output_file}")

if __name__ == "__main__":
    build_llm_dataset()