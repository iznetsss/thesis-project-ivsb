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
        # Looking for public/private/protected and '('
        if re.search(r'\b(public|private|protected)\b.*\(', lines[i]):
            start_idx = i
            break

    # Downward Search (Method End) - Brace Counter
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
        # Case A: Standard Method
        return [(i + 1, lines[i].rstrip()) for i in range(start_idx, end_idx + 1)]
    else:
        # Case B: Extreme Method
        result = []
        head_end = min(start_idx + 10, end_idx)

        # Header
        for i in range(start_idx, head_end + 1):
            result.append((i + 1, lines[i].rstrip()))

        result.append((None, "// ... [code skipped] ..."))

        # Window (50 before, 50 after target)
        win_start = max(head_end + 1, target_idx - 50)
        win_end = min(end_idx - 1, target_idx + 50)

        for i in range(win_start, win_end + 1):
            result.append((i + 1, lines[i].rstrip()))

        if win_end < end_idx - 1:
            result.append((None, "// ... [code skipped] ..."))

        # Footer
        result.append((end_idx + 1, lines[end_idx].rstrip()))
        return result


def format_code_block(context_lines, target_line):
    """Formats the context into Markdown with line numbers and vulnerability marker."""
    formatted = ["```java"]
    for line_num, text in context_lines:
        if line_num is None:  # Separator line
            formatted.append(text)
        else:
            prefix = ">> " if line_num == target_line else "   "
            # Format: '>> 72: String path = ...'
            formatted.append(f"{prefix}{line_num}: {text}")
    formatted.append("```")
    return "\n".join(formatted)


def build_llm_dataset():
    base_dir = Path(__file__).parent.parent
    input_file = base_dir / "results" / "initial_scan.json"
    output_file = base_dir / "results" / "llm_prompts.json"

    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    findings = data.get("results", [])
    processed_data = []

    print("Parsing Java files and generating context for LLM...")

    for item in findings:
        rel_path = Path(item["path"])

        # Skip excluded directories (sanity check)
        if "other_files" in str(rel_path):
            continue

        abs_file_path = base_dir / rel_path
        target_line = item["start"]["line"]
        target_idx = target_line - 1  # 0-based index for Python

        if not abs_file_path.exists():
            continue

        with open(abs_file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Execute parser logic
        global_context = get_global_header(lines)
        start_idx, end_idx = find_method_boundaries(lines, target_idx)
        context_lines = extract_semantic_context(lines, start_idx, end_idx, target_idx)
        code_context = format_code_block(context_lines, target_line)

        # Metadata extraction
        cwe_list = item["extra"]["metadata"].get("cwe", ["Unknown"])
        cwe_string = cwe_list[0] if cwe_list else "Unknown"

        # Build final object
        finding_info = {
            "meta": {
                "cwe": cwe_string,
                "message": item["extra"]["message"],
                "file_path": str(rel_path)
            },
            "global_context": global_context,
            "code_context": code_context
        }

        processed_data.append(finding_info)

    # Save to JSON
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(processed_data, f, indent=4)

    print(f"Success! Extracted context for {len(processed_data)} findings.")
    print(f"Saved dataset to: {output_file}")


if __name__ == "__main__":
    build_llm_dataset()