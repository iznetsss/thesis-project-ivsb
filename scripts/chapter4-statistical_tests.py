import scipy.stats as stats
from statsmodels.stats.contingency_tables import mcnemar

"""
Script for calculating statistical significance (p-values) for Research Questions 1-3.
Standard significance threshold: alpha = 0.05.
Results where p < 0.001 are considered highly significant.
"""

print("=== STATISTICAL SIGNIFICANCE TESTS ===")

# -----------------------------------------------------------------------------
# RQ1: Chi-Square Test of Independence (Failure Rates: Qwen_abl vs GPT-5 Nano)
# -----------------------------------------------------------------------------
# Evaluates if the operational reliability (Fail vs Pass) differs significantly
# between local and cloud deployments.
# Contingency Table format: [[Model1_Fail, Model1_Pass], [Model2_Fail, Model2_Pass]]
rq1_table = [
    [0, 1975],   # Qwen_abl: 0 failures out of 1975
    [84, 1891]   # GPT-5 Nano: 84 failures out of 1975
]

chi2, p_rq1, dof, expected = stats.chi2_contingency(rq1_table)
print(f"RQ1 (Chi-Square) p-value: {p_rq1:.2e}")
# Interpretation: p < 0.001 indicates a systematic difference in reliability.


# -----------------------------------------------------------------------------
# RQ2: McNemar's Test (Recall/Censorship: Qwen_std vs Qwen_abl)
# -----------------------------------------------------------------------------
# Evaluates paired nominal data (classification outcomes on the same 1975 files).
# Used to determine if the 'abliteration' intervention significantly improved Recall.
# Table format: [[Both_Correct, Std_Correct/Abl_Wrong], [Abl_Correct/Std_Wrong, Both_Wrong]]
# Based on delta: Abliterated found 456 additional vulnerabilities missed by Standard.
rq2_table = [
    [451, 0],    # Cases where both found the bug / Std was the only one right
    [456, 366]   # Cases where Abl was the only one right / Both missed it
]

result_rq2 = mcnemar(rq2_table, exact=False, correction=True)
print(f"RQ2 (McNemar) p-value: {result_rq2.pvalue:.2e}")
# Interpretation: p < 0.001 proves the impact of weight abliteration is non-random.


# -----------------------------------------------------------------------------
# RQ3: McNemar's Test (Frontier reasoning vs SLM on 200 conflict files)
# -----------------------------------------------------------------------------
# Evaluates if the reasoning gap between Claude Opus and Qwen_abl is significant
# on the high-complexity subset.
# Out of 200 files, Opus correctly resolved 50 cases where Qwen_abl failed.
rq3_table = [
    [100, 50],   # Both right / Opus only right
    [0, 50]      # Qwen only right / Both wrong
]

result_rq3 = mcnemar(rq3_table, exact=False, correction=True)
print(f"RQ3 (McNemar) p-value: {result_rq3.pvalue:.2e}")
# Interpretation: p < 0.001 validates the existence of a 'reasoning ceiling' for SLMs.

print("=======================================")