import json
import sys
import os
from pathlib import Path  # Добавил для надежности путей


def evaluate_metrics(json_file_path):
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        sys.exit(1)

    total_files = len(data)
    errors_refusals = 0

    tp_count = 0
    fn_count = 0
    tn_count = 0
    fp_count = 0

    for item in data:
        # Ground truth: TP and FN mean the file is actually vulnerable. FP means safe.
        gt = item.get("ground_truth", "").upper()

        analysis = item.get("analysis")
        if not analysis or not isinstance(analysis, dict) or "verdict" not in analysis:
            errors_refusals += 1
            continue

        verdict = analysis.get("verdict", "").strip().lower()

        # Parse AI verdict
        ai_says_vulnerable = "true positive" in verdict
        ai_says_safe = "false positive" in verdict

        if not ai_says_vulnerable and not ai_says_safe:
            errors_refusals += 1
            continue

        # Matrix Calculation
        if gt in ["TP", "FN"]:  # Actually vulnerable
            if ai_says_vulnerable:
                tp_count += 1
            elif ai_says_safe:
                fn_count += 1
        elif gt == "FP":  # Actually safe
            if ai_says_safe:
                tn_count += 1
            elif ai_says_vulnerable:
                fp_count += 1
        else:
            # Unknown ground truth format
            errors_refusals += 1

    # Metrics computation
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fprr = tn_count / (tn_count + fp_count) if (tn_count + fp_count) > 0 else 0.0

    print("=== METRICS EVALUATION ===")
    print(f"Total Files Analyzed: {total_files}")
    print(f"Errors / Refusals:    {errors_refusals}")
    print("-" * 26)
    print(f"True Positives (TP):  {tp_count}")
    print(f"False Positives (FP): {fp_count}")
    print(f"True Negatives (TN):  {tn_count}")
    print(f"False Negatives (FN): {fn_count}")
    print("-" * 26)
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1_score:.4f}")
    print(f"FPRR:      {fprr:.4f} (False Positive Reduction Rate)")


if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent
    default_path = base_dir / "results" / "audit_results.json"

    # Use argument if provided, otherwise fallback to default
    target_file = sys.argv[1] if len(sys.argv) > 1 else default_path

    # Sanity check to inform if the path is wrong
    if not os.path.exists(target_file):
        print(f"Warning: The file was not found at {target_file}")
        sys.exit(1)

    evaluate_metrics(target_file)