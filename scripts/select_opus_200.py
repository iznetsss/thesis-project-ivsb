import json
import random
from pathlib import Path

# Result filenames
RESULT_FILES = {
    "qwen_abl": "qwen4b_abliterated.json",
    "qwen_std": "qwen4b.json",
    "gemma": "gemma3.json",
    "gpt5": "gpt_5_nano.json"
}


def get_verdict(item):
    v = str(item['analysis'].get('verdict', '')).upper()
    return "TP" if "TRUE" in v else "FP"


def balanced_sample(file_list, target_count, all_data):
    """Samples files while maintaining a 50/50 balance of TP and FP ground truth."""
    tp_pool = [f for f in file_list if all_data['qwen_abl'][f]['ground_truth'] in ['TP', 'FN']]
    fp_pool = [f for f in file_list if all_data['qwen_abl'][f]['ground_truth'] == 'FP']

    selected = []
    half = target_count // 2

    # Take equal amounts from both pools
    selected += random.sample(tp_pool, min(len(tp_pool), half))
    remaining_needed = target_count - len(selected)
    selected += random.sample(fp_pool, min(len(fp_pool), remaining_needed))

    # If one pool was too small, fill from the other to reach target_count
    if len(selected) < target_count:
        still_needed = target_count - len(selected)
        leftover_pool = [f for f in file_list if f not in selected]
        selected += random.sample(leftover_pool, min(len(leftover_pool), still_needed))

    return selected


def select_opus_batch():
    base_dir = Path(__file__).parent.parent
    res_dir = base_dir / "results" / "models_results"

    all_data = {}
    for key, filename in RESULT_FILES.items():
        path = res_dir / filename
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                all_data[key] = {item['file']: item for item in json.load(f)}
        else:
            print(f"[!] Missing file: {filename}")
            return

    common_files = list(set.intersection(*(set(d.keys()) for d in all_data.values())))

    cat_censorship = []  # Abliterated vs Standard
    cat_titans = []  # GPT5 vs Abliterated
    cat_blind = []  # FN cases (Blind Audit)
    cat_other = []

    for fname in common_files:
        v_abl = get_verdict(all_data['qwen_abl'][fname])
        v_std = get_verdict(all_data['qwen_std'][fname])
        v_gpt = get_verdict(all_data['gpt5'][fname])
        gt = all_data['qwen_abl'][fname]['ground_truth']

        if gt == "FN":  # Prioritize Blind Audit (False Negatives)
            cat_blind.append(fname)
        elif v_abl == "TP" and v_std == "FP":
            cat_censorship.append(fname)
        elif v_abl != v_gpt:
            cat_titans.append(fname)
        else:
            cat_other.append(fname)

    random.seed(42)

    selected = []
    # 1. 30 Blind Audit files (Critical for checking if Opus finds hidden bugs)
    selected += random.sample(cat_blind, min(len(cat_blind), 30))
    # 2. 80 Censorship Gap (Balanced TP/FP)
    selected += balanced_sample(cat_censorship, 80, all_data)
    # 3. 90 Model Clash (Balanced TP/FP)
    selected += balanced_sample(cat_titans, 90, all_data)

    # Metadata for review
    metadata = {}
    stats = {"TP/FN": 0, "FP": 0}

    for fname in selected:
        gt = all_data['qwen_abl'][fname]['ground_truth']
        stats["TP/FN" if gt in ["TP", "FN"] else "FP"] += 1

        group = "Other"
        if fname in cat_blind:
            group = "Blind Audit (FN)"
        elif fname in cat_censorship:
            group = "Censorship Gap"
        elif fname in cat_titans:
            group = "Model Clash"

        metadata[fname] = {
            "group": group,
            "ground_truth": gt,
            "qwen_abl": get_verdict(all_data['qwen_abl'][fname]),
            "gpt5": get_verdict(all_data['gpt5'][fname])
        }

    # Save outputs
    with open(base_dir / "results" / "opus_queue_200.json", 'w') as f:
        json.dump(selected, f, indent=4)
    with open(base_dir / "results" / "opus_queue_metadata.json", 'w') as f:
        json.dump(metadata, f, indent=4)

    print(f"\n[+] Selected 200 files for Opus:")
    print(f"    - Blind Audit (FN): {len([f for f in selected if f in cat_blind])}")
    print(f"    - Censorship Gap:   {len([f for f in selected if f in cat_censorship])}")
    print(f"    - Model Clash:      {len([f for f in selected if f in cat_titans])}")
    print(f"\n[+] Final Ground Truth Balance:")
    print(f"    - Vulnerable (TP/FN): {stats['TP/FN']}")
    print(f"    - Safe (FP):          {stats['FP']}")


if __name__ == "__main__":
    select_opus_batch()