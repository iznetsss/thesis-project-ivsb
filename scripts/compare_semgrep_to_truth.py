import json
import csv
from pathlib import Path


def run_comparison():
    base_dir = Path(__file__).parent.parent
    semgrep_file = base_dir / "results" / "initial_scan.json"
    truth_file = base_dir / "data" / "expectedresults_full.csv"
    output_report = base_dir / "results" / "semgrep_accuracy_report.csv"

    # Load findings
    with open(semgrep_file, 'r', encoding='utf-8') as f:
        semgrep_data = json.load(f)

    # Scrutinize the paths
    found_files = {Path(result['path']).name for result in semgrep_data.get('results', [])}

    truth_data = {}
    with open(truth_file, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)

        # Manifestly check headers once
        headers = [h.strip() for h in reader.fieldnames]
        print(f"DEBUG: Detected CSV Headers -> {headers}")
        reader.fieldnames = headers

        for row in reader:
            # Opaque mapping: check common variations of the column names
            t_name = row.get('testName') or row.get('testname') or row.get('test_name') or list(row.values())[0]
            v_status = row.get('vulnerability') or row.get('Vulnerability') or list(row.values())[2]

            if t_name:
                # Normalize filename
                clean_name = t_name.strip()
                if not clean_name.endswith(".java"):
                    clean_name += ".java"

                is_vuln = str(v_status).strip().lower() == 'true'
                truth_data[clean_name] = is_vuln

    print(f"Total files loaded from CSV: {len(truth_data)}")

    stats = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    comparison_results = []

    if not truth_data:
        print("No data parsed from CSV. Check header names.")
        return

    for file_name, actually_vuln in truth_data.items():
        semgrep_found = file_name in found_files

        if actually_vuln and semgrep_found:
            res_type = "TP (True Positive)"
            stats["TP"] += 1
        elif not actually_vuln and semgrep_found:
            res_type = "FP (False Positive)"
            stats["FP"] += 1
        elif actually_vuln and not semgrep_found:
            res_type = "FN (False Negative)"
            stats["FN"] += 1
        else:
            res_type = "TN (True Negative)"
            stats["TN"] += 1

        comparison_results.append({
            "filename": file_name,
            "actually_vulnerable": actually_vuln,
            "semgrep_found": semgrep_found,
            "type": res_type
        })

    with open(output_report, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["filename", "actually_vulnerable", "semgrep_found", "type"])
        writer.writeheader()
        writer.writerows(comparison_results)

    print("\n--- SEMGREP ACCURACY STATS ---")
    for k, v in stats.items():
        print(f"{k}: {v}")

    total_pos = stats["TP"] + stats["FP"]
    total_actual_pos = stats["TP"] + stats["FN"]

    precision = stats["TP"] / total_pos if total_pos > 0 else 0
    recall = stats["TP"] / total_actual_pos if total_actual_pos > 0 else 0

    print(f"\nPrecision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    print(f"Report saved to: {output_report}")


if __name__ == "__main__":
    run_comparison()