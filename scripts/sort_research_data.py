import csv
import shutil
from pathlib import Path


def sort_files():
    # Define primary directories
    base_dir = Path(__file__).parent.parent
    source_dir = base_dir / "data" / "benchmark_source"
    report_file = base_dir / "results" / "semgrep_accuracy_report.csv"

    # Target destinations
    research_base = source_dir / "research_files"
    fp_dir = research_base / "false_positives"
    fn_dir = research_base / "false_negatives"
    archive_dir = source_dir / "corpus_storage"

    # Create directory structure if missing
    for d in [fp_dir, fn_dir, archive_dir]:
        d.mkdir(parents=True, exist_ok=True)

    print("Commencing file migration...")

    # Open the map (CSV report)
    with open(report_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            filename = row['filename']
            res_type = row['type']
            src_path = source_dir / filename

            # Skip if file was already moved or missing
            if not src_path.exists():
                continue

            # Determine trajectory
            if "FP" in res_type:
                dest = fp_dir / filename
            elif "FN" in res_type:
                dest = fn_dir / filename
            else:
                dest = archive_dir / filename

            # Execute relocation
            shutil.move(str(src_path), str(dest))

    print(f"Migration complete.")
    print(f" -> FP: {len(list(fp_dir.glob('*.java')))}")
    print(f" -> FN: {len(list(fn_dir.glob('*.java')))}")
    print(f" -> Archive: {len(list(archive_dir.glob('*.java')))}")


if __name__ == "__main__":
    sort_files()