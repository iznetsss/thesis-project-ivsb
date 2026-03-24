# Automatically migrates and organizes source files into research-specific directories based on scanner performance.
import csv
import shutil
from pathlib import Path

def sort_files():
    base_dir = Path(__file__).parent.parent
    source_dir = base_dir / "data" / "benchmark_source"
    report_file = base_dir / "results" / "semgrep_accuracy_report.csv"

    # Define new target directories
    research_base = source_dir / "research_files"
    tp_dir = research_base / "sast_alerts" / "true_positives"
    fp_dir = research_base / "sast_alerts" / "false_positives"
    fn_dir = research_base / "blind_test" / "false_negatives"
    archive_dir = source_dir / "corpus_storage"

    for d in [tp_dir, fp_dir, fn_dir, archive_dir]:
        d.mkdir(parents=True, exist_ok=True)

    print("Migrating files...")

    with open(report_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            filename = row['filename']
            res_type = row['type']
            src_path = source_dir / filename

            if not src_path.exists():
                continue

            # Route files based on Semgrep performance
            if "TP" in res_type:
                dest = tp_dir / filename
            elif "FP" in res_type:
                dest = fp_dir / filename
            elif "FN" in res_type:
                dest = fn_dir / filename
            else:
                dest = archive_dir / filename

            shutil.move(str(src_path), str(dest))

    print("Migration complete.")
    print(f" -> SAST Alerts (TP): {len(list(tp_dir.glob('*.java')))}")
    print(f" -> SAST Alerts (FP): {len(list(fp_dir.glob('*.java')))}")
    print(f" -> Blind Test (FN):  {len(list(fn_dir.glob('*.java')))}")
    print(f" -> Archive (TN):     {len(list(archive_dir.glob('*.java')))}")

if __name__ == "__main__":
    sort_files()