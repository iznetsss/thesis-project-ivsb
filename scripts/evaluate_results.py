import json
from pathlib import Path
from collections import defaultdict

# Model config
MODELS = {
    "qwen_abl": "qwen4b_abliterated.json",
    "qwen_std": "qwen4b.json",
    "gpt5": "gpt_5_nano.json",
    "gemma": "gemma3.json",
    "opus": "claude_opus_4_6.json"
}


def load_data(res_dir):
    """Load all JSON results into a unified dict."""
    data = defaultdict(dict)

    for model_name, filename in MODELS.items():
        path = res_dir / filename
        if not path.exists():
            continue

        with open(path, 'r', encoding='utf-8') as f:
            try:
                records = json.load(f)
                for r in records:
                    fname = r['file']
                    # Handle raw outputs or specific JSON structure
                    verdict_str = str(r.get('analysis', {}).get('verdict', '')).upper()

                    if "TRUE" in verdict_str:
                        ai_says_vuln = True
                    elif "FALSE" in verdict_str:
                        ai_says_vuln = False
                    else:
                        ai_says_vuln = None  # Parse fail / Censored

                    data[fname][model_name] = {
                        "ai_vuln": ai_says_vuln,
                        "gt_vuln": r['ground_truth'] == "TP",
                        "cwe": r.get('cwe', 'Unknown')
                    }
            except Exception as e:
                print(f"[!] Err loading {filename}: {e}")

    return data


def calc_metrics(stats):
    """Compute P, R, F1 from raw counts."""
    tp, fp, fn, tn = stats['TP'], stats['FP'], stats['FN'], stats['TN']

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return precision, recall, f1


def get_confusion_matrix(model_data):
    """Map AI verdicts to TP/FP/TN/FN."""
    stats = {'TP': 0, 'FP': 0, 'FN': 0, 'TN': 0, 'FAIL': 0}
    for item in model_data:
        ai = item['ai_vuln']
        gt = item['gt_vuln']

        if ai is None:
            stats['FAIL'] += 1
        elif ai and gt:
            stats['TP'] += 1
        elif ai and not gt:
            stats['FP'] += 1
        elif not ai and gt:
            stats['FN'] += 1
        elif not ai and not gt:
            stats['TN'] += 1

    return stats


def run_evaluation():
    base_dir = Path(__file__).parent.parent
    res_dir = base_dir / "results" / "models_results"

    data = load_data(res_dir)
    print(f"Loaded data for {len(data)} unique files.\n")

    # --- 1. GLOBAL METRICS ---
    print("=" * 60)
    print("1. GLOBAL QUANTITATIVE ANALYSIS (All available files)")
    print("=" * 60)
    print(
        f"{'Model':<12} | {'TP':<4} | {'FP':<4} | {'FN':<4} | {'TN':<4} | {'FAIL':<4} | {'Prec':<6} | {'Rec':<6} | {'F1':<6}")
    print("-" * 80)

    for model in MODELS.keys():
        model_records = [d[model] for d in data.values() if model in d]
        if not model_records: continue

        stats = get_confusion_matrix(model_records)
        p, r, f1 = calc_metrics(stats)
        print(
            f"{model:<12} | {stats['TP']:<4} | {stats['FP']:<4} | {stats['FN']:<4} | {stats['TN']:<4} | {stats['FAIL']:<4} | {p:.4f} | {r:.4f} | {f1:.4f}")

    # --- ABLITERATION IMPACT (Standard vs Abliterated Qwen) ---
    print("\n" + "=" * 60)
    print("2. ABLITERATION IMPACT (Qwen Std vs Qwen Abl)")
    print("=" * 60)
    common_qwen = [f for f, d in data.items() if 'qwen_std' in d and 'qwen_abl' in d]

    q_std_stats = get_confusion_matrix([data[f]['qwen_std'] for f in common_qwen])
    q_abl_stats = get_confusion_matrix([data[f]['qwen_abl'] for f in common_qwen])

    p_std, r_std, _ = calc_metrics(q_std_stats)
    p_abl, r_abl, _ = calc_metrics(q_abl_stats)

    print(f"Dataset size: {len(common_qwen)} files")
    print(f"Delta Recall:    {(r_abl - r_std):+.4f} (Abliterated finds more/less bugs)")
    print(f"Delta Precision: {(p_abl - p_std):+.4f} (Abliterated is more/less accurate)")
    print(f"Censorship (Failures): Std = {q_std_stats['FAIL']}, Abl = {q_abl_stats['FAIL']}")

    # --- Intersection of Opus and Qwen ---
    print("\n" + "=" * 60)
    print("3. WEIGHT CLASS COMPARISON (Only the 200 Opus files)")
    print("=" * 60)

    # Filter only files analyzed by Opus
    opus_files = [f for f, d in data.items() if 'opus' in d]

    if opus_files:
        print(f"{'Model':<12} | {'Prec':<6} | {'Rec':<6} | {'F1':<6}")
        print("-" * 40)

        for model in ['opus', 'qwen_abl', 'gpt5']:
            if any(model not in data[f] for f in opus_files): continue

            stats = get_confusion_matrix([data[f][model] for f in opus_files])
            p, r, f1 = calc_metrics(stats)
            print(f"{model:<12} | {p:.4f} | {r:.4f} | {f1:.4f}")

        # Golden Standard Check
        opus_right_qwen_wrong = 0
        for f in opus_files:
            o_ai, q_ai, gt = data[f]['opus']['ai_vuln'], data[f]['qwen_abl']['ai_vuln'], data[f]['opus']['gt_vuln']
            if o_ai == gt and q_ai != gt:
                opus_right_qwen_wrong += 1

        print(f"\nFiles where Opus was right but Qwen Abliterated failed: {opus_right_qwen_wrong} / {len(opus_files)}")
    else:
        print("Opus results not found.")


if __name__ == "__main__":
    run_evaluation()