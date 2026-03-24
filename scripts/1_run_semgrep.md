# Execution guide and shell commands to perform the baseline SAST scan using Semgrep.
# Create virtual environment
python -m venv venv

# Activate environment
.\venv\Scripts\activate

# Install dependencies
pip install semgrep

# Ensure UTF-8 encoding for Windows
$env:PYTHONUTF8 = "1"

# Execute Semgrep scan
semgrep scan --config auto ./data/benchmark_source --exclude "other_files_31-2740" --json --output ./results/initial_scan.json
