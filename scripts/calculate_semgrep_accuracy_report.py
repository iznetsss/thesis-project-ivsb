import csv
from pathlib import Path


def calculate_stats():
    base_dir = Path(__file__).parent.parent
    report_file = base_dir / "results" / "semgrep_accuracy_report.csv"

    stats = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

    with open(report_file, 'r', encoding='utf-8') as f:
        # Use DictReader to handle columns by name
        reader = csv.DictReader(f)
        for row in reader:
            res_type = row['type'].split(' ')[0]  # Extract TP, FP, etc.
            if res_type in stats:
                stats[res_type] += 1

    total = sum(stats.values())

    print("--- Semgrep Accuracy Baseline ---")
    print(f"Total Files: {total}")
    print(f"TP: {stats['TP']} | FP: {stats['FP']}")
    print(f"TN: {stats['TN']} | FN: {stats['FN']}")


if __name__ == "__main__":
    calculate_stats()