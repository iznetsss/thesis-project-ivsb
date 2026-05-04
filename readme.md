# LLM-Enhanced SAST: Reducing False Positives and Improving Prioritization

**Author:** Ivan Kuznetsov (233767IVSB)
**Institution:** Tallinn University of Technology (School of Information Technologies)
**Year:** 2026
**Type:** Bachelor's Thesis

---

## 1. Overview

Static Application Security Testing (SAST) tools frequently generate high volumes of false-positive alerts, leading to operational "alert fatigue." This repository contains the automated evaluation pipeline and dataset used to investigate the efficacy of local, privacy-preserving Small Language Models (SLMs) in SAST alert triage.

The thesis proposes a Hybrid DevSecOps Architecture: utilizing local, abliterated (safety-uncensored) SLMs for zero-cost baseline noise reduction, while escalating high-complexity edge cases to frontier cloud APIs.

## 2. Repository Structure

project/
├── data/                         # Ground truth and source code repository
│   ├── benchmark_source/         # Java source files from OWASP Benchmark
│   │   ├── research_files/       # Files categorized for LLM analysis
│   │   │   ├── blind_test/       # False Negatives (missed by SAST)
│   │   │   └── sast_alerts/      # True Positives and False Positives from SAST
│   │   └── corpus_storage/       # Archive for non-vulnerable (True Negatives)
│   └── expectedresults_full.csv  # OWASP Benchmark ground truth
│
├── results/                      # Outputs from scanners and language models
│   ├── models_results/           # Raw JSON verdicts from evaluated LLMs
│   ├── initial_scan.json         # Baseline results from Semgrep
│   ├── llm_prompts.json          # Dataset with extracted semantic context
│   ├── opus_queue_200.json       # Subset for high-cost model testing
│   └── semgrep_accuracy_report.csv # Baseline scanner comparison
│
├── scripts/                      # Automated research pipeline (steps 1–8)
│   ├── 1_run_semgrep.md              # Instructions for initial scan
│   ├── 2_compare_semgrep_to_truth.py # Validate scanner findings
│   ├── 3_calculate_semgrep_accuracy.py # Generate baseline metrics
│   ├── 4_sort_research_data.py       # File classification and migration
│   ├── 5_parse_java_context.py       # Method-level semantic extraction
│   ├── 6_select_opus_200.py          # Conflict-based sampling logic
│   ├── 7_run_llm_audit.py            # LLM orchestration engine
│   ├── 8_evaluate_results.py         # Final evaluation metrics
│   └── chapter4-statistical_tests.py # Statistical significance tests
│
├── .env                            # API keys and environment variables
├── java_parsing_structure.md       # Context parser technical specification
└── requirements.txt                # Project dependencies


## 3. Requirements

*   Python 3.x
*   Dependencies: `openai`, `anthropic`, `python-dotenv`
*   SAST Engine: `semgrep`
*   Hardware: Local execution requires a consumer-grade GPU (Minimum 6GB VRAM for 4-bit quantized 4B-parameter models).

## 4. Usage / Execution Pipeline

To replicate the experimental methodology, execute the scripts sequentially:

1.  **Baseline Generation:** Execute SAST scan via `scripts/1_run_semgrep.md`.
2.  **Validation:** Run scripts `2` and `3` to cross-reference findings against ground truth.
3.  **Data Structuring:** Run script `4` for file classification.
4.  **Context Parsing:** Execute `5_parse_java_context.py` to extract semantic method blocks.
5.  **LLM Audit:** Execute `7_run_llm_audit.py` to prompt local/cloud models (outputs structured JSON verdicts).
6.  **Evaluation:** Run script `8` and the statistical tests script to compute Precision, Recall, F1-scores, and statistical significance.

## 5. License

The source code in this repository is licensed under the MIT License. 
The thesis text and its contents are subject to the non-exclusive reproduction and publication license granted to Tallinn University of Technology, with the author retaining all other intellectual property rights.