# IP prioritization validation, 2026-09-21

The preselected share-weighted challenger passed the held-out promotion gate. Policy 3 promotes it in the GUI. The unusualness GUI ordering remains unchanged. All corpus security runs include CRS at paranoia level 2.

## Method and limitations

Development used the previously examined medium corpus and seeds 13, 19, 23 and 31. The challenger was frozen before seeds 41, 53, 67 and 71 were scored. Broken-links traffic is a separate all-benign stress case. These are related synthetic workloads, not ten independent real-world environments. The acceptance thresholds are engineering criteria, not statistical guarantees.

Operational recall covers every judged attack-associated client. Matched comparisons restrict all methods to at least 20 requests and 20 observed statuses, recompute feature percentiles there, and refit the model. Suspicious queues retain quiet clients in operational comparisons. Unknown request categories exclude a client only when no request establishes a known hostile positive. Missing or mismatched line judgments are rejected. Explicit exclusions are listed below; excluded unknown clients are not counted as benign.

Tables use relevant clients found per available investigation slot (yield), not precision among a short returned queue. Available slots are min(budget, judged population). Raw records also include actual reviewed count, precision, recall, eligibility counts, exclusions, maximum attainable recall and the entire returned-ranking recall curve. Undefined quantities are marked n/a. The raw method key suspicious denotes the frozen severity-first baseline; share denotes the promoted queue.

Isolation Forest uses seeds 7, 19, 42, 73 and 101; 42 is primary throughout. It uses the same behavioral fields without identity or detection labels. Each record includes ordered features, median imputation, missing indicators, log1p count transformations, sklearn version, tree count, sample count and seed. Model scores are unusualness rankings, not attack probabilities. Attack-label scoring of statistical and model methods is a secondary security-retrieval diagnostic, not unusualness accuracy.

## Population accounting

| Case | Observed IPs | Judged IPs | Attack IPs | Base rate | Quiet attack IPs | Matched IPs / attack IPs | Statistical attack recall ceiling |
|---|---:|---:|---:|---:|---:|---:|---:|
| medium | 2760 | 2757 | 399 | 14.47% | 342 | 2059 / 57 | 14.29% |
| 13 | 931 | 928 | 147 | 15.84% | 121 | 682 / 26 | 17.69% |
| 19 | 931 | 928 | 133 | 14.33% | 102 | 708 / 31 | 23.31% |
| 23 | 942 | 939 | 125 | 13.31% | 101 | 692 / 24 | 19.20% |
| 31 | 939 | 936 | 126 | 13.46% | 104 | 711 / 22 | 17.46% |
| 41 | 957 | 954 | 135 | 14.15% | 114 | 706 / 21 | 15.56% |
| 53 | 973 | 970 | 132 | 13.61% | 107 | 727 / 25 | 18.94% |
| 67 | 939 | 936 | 129 | 13.78% | 105 | 696 / 24 | 18.60% |
| 71 | 969 | 966 | 135 | 13.98% | 115 | 713 / 20 | 14.81% |
| broken-links | 1510 | 1510 | 0 | 0.00% | 0 | 348 / 0 | n/a |

Judgment exclusions: medium: {'127.0.0.1': 'unknown request ground truth', '203.0.113.2': 'unknown request ground truth', '203.0.113.3': 'unknown request ground truth'}; 13: {'127.0.0.1': 'unknown request ground truth', '203.0.113.2': 'unknown request ground truth', '203.0.113.3': 'unknown request ground truth'}; 19: {'127.0.0.1': 'unknown request ground truth', '203.0.113.2': 'unknown request ground truth', '203.0.113.3': 'unknown request ground truth'}; 23: {'127.0.0.1': 'unknown request ground truth', '203.0.113.2': 'unknown request ground truth', '203.0.113.3': 'unknown request ground truth'}; 31: {'127.0.0.1': 'unknown request ground truth', '203.0.113.2': 'unknown request ground truth', '203.0.113.3': 'unknown request ground truth'}; 41: {'127.0.0.1': 'unknown request ground truth', '203.0.113.2': 'unknown request ground truth', '203.0.113.3': 'unknown request ground truth'}; 53: {'127.0.0.1': 'unknown request ground truth', '203.0.113.2': 'unknown request ground truth', '203.0.113.3': 'unknown request ground truth'}; 67: {'127.0.0.1': 'unknown request ground truth', '203.0.113.2': 'unknown request ground truth', '203.0.113.3': 'unknown request ground truth'}; 71: {'127.0.0.1': 'unknown request ground truth', '203.0.113.2': 'unknown request ground truth', '203.0.113.3': 'unknown request ground truth'}; broken-links: none

## Selection and held-out gate

The fixed candidates were supporting requests first; log2(1+h) x (1+s/4); and that bounded severity score multiplied by 0.5+0.5*h/n. Ties use the declared category/path/support/IP ordering. These are experimental priority scores, not probabilities.

The declared development selection criteria were mean yield at budgets 10 and 25, then yield at 50, quiet-attack recall at 50, and candidate order. All three candidates achieved 100% yield at budgets 10, 25 and 50 on every development case. The primary criterion and first tiebreak therefore had no discriminating power. Frozen choice: **share**, decided solely by mean quiet-attack recall at 50: 22.602% for share, 22.149% for support and 21.596% for weighted. Share's advantage over support was 0.453 percentage points. These results offer limited evidence for choosing among the candidates.

| Development case | Method | Yield 10 | Yield 25 | Yield 50 | Quiet recall 50 |
|---|---|---:|---:|---:|---:|
| medium | suspicious | 50.00% | 60.00% | 80.00% | 0.00% |
| medium | support | 100.00% | 100.00% | 100.00% | 0.00% |
| medium | weighted | 100.00% | 100.00% | 100.00% | 0.00% |
| medium | share | 100.00% | 100.00% | 100.00% | 0.29% |
| 13 | suspicious | 90.00% | 96.00% | 98.00% | 27.27% |
| 13 | support | 100.00% | 100.00% | 100.00% | 24.79% |
| 13 | weighted | 100.00% | 100.00% | 100.00% | 23.97% |
| 13 | share | 100.00% | 100.00% | 100.00% | 24.79% |
| 19 | suspicious | 80.00% | 92.00% | 96.00% | 24.51% |
| 19 | support | 100.00% | 100.00% | 100.00% | 23.53% |
| 19 | weighted | 100.00% | 100.00% | 100.00% | 22.55% |
| 19 | share | 100.00% | 100.00% | 100.00% | 24.51% |
| 23 | suspicious | 60.00% | 84.00% | 92.00% | 29.70% |
| 23 | support | 100.00% | 100.00% | 100.00% | 30.69% |
| 23 | weighted | 100.00% | 100.00% | 100.00% | 30.69% |
| 23 | share | 100.00% | 100.00% | 100.00% | 31.68% |
| 31 | suspicious | 60.00% | 84.00% | 92.00% | 29.81% |
| 31 | support | 100.00% | 100.00% | 100.00% | 31.73% |
| 31 | weighted | 100.00% | 100.00% | 100.00% | 30.77% |
| 31 | share | 100.00% | 100.00% | 100.00% | 31.73% |

| Held-out case | Baseline hits 10 | Challenger hits 10 | Baseline quiet recall 50 | Challenger quiet recall 50 |
|---|---:|---:|---:|---:|
| 41 | 4 | 10 | 26.32% | 28.95% |
| 53 | 5 | 10 | 26.17% | 28.04% |
| 67 | 7 | 10 | 29.52% | 29.52% |
| 71 | 9 | 10 | 32.17% | 30.43% |

Promotion: **passed**. Mean held-out yield changes: yield10 +0.3750, yield25 +0.1500, yield50 +0.0750, quiet50 +0.0069. Every gate check passed. On seed 71, quiet recall at 50 fell from 32.17% to 30.43% (two clients); the agreed gate constrains the mean quiet recall, which improved. This per-case regression remains relevant.

All three candidates also achieved 100% held-out yield at budgets 10, 25 and 50 and would pass the same gate. Their yield improvements were identical; their mean quiet-recall changes differed (support +0.00254, weighted +0.00020, share +0.00690). The gate confirms improvement over the severity-first baseline, but does not distinguish which candidate to choose. The development choice remains frozen; this held-out comparison does not retune it.

## Per-case security retrieval

### medium

Operational population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 399 / 0 | 2757 | 20.00% | 8.00% | 10.00% | 7.00% | 4.00% | 100.00% |
| errors | 399 / 0 | 2757 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| suspicious | 395 / 4 | 405 | 50.00% | 60.00% | 80.00% | 90.00% | 96.00% | 99.00% |
| support | 395 / 4 | 405 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 99.00% |
| weighted | 395 / 4 | 405 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 99.00% |
| share | 395 / 4 | 405 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 99.00% |
| statistics | 57 / 342 | 2054 | 50.00% | 24.00% | 16.00% | 8.00% | 19.20% | 14.29% |
| group_sum | 57 / 342 | 2054 | 30.00% | 16.00% | 10.00% | 5.00% | 3.20% | 14.29% |
| group_top2 | 57 / 342 | 2054 | 30.00% | 16.00% | 18.00% | 12.00% | 11.60% | 14.29% |
| isolation_forest | 57 / 342 | 2059 | 100.00% | 96.00% | 78.00% | 55.00% | 22.40% | 14.29% |

Matched population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 57 / 0 | 2059 | 20.00% | 8.00% | 10.00% | 7.00% | 4.00% | 100.00% |
| errors | 57 / 0 | 2059 | 100.00% | 100.00% | 100.00% | 53.00% | 21.60% | 100.00% |
| suspicious | 53 / 4 | 63 | 50.00% | 60.00% | 80.00% | 53.00% | 21.20% | 92.98% |
| support | 53 / 4 | 63 | 100.00% | 100.00% | 100.00% | 53.00% | 21.20% | 92.98% |
| weighted | 53 / 4 | 63 | 100.00% | 100.00% | 100.00% | 53.00% | 21.20% | 92.98% |
| share | 53 / 4 | 63 | 100.00% | 100.00% | 100.00% | 53.00% | 21.20% | 92.98% |
| statistics | 57 / 0 | 2054 | 50.00% | 24.00% | 16.00% | 8.00% | 19.20% | 100.00% |
| group_sum | 57 / 0 | 2054 | 30.00% | 16.00% | 10.00% | 5.00% | 3.20% | 100.00% |
| group_top2 | 57 / 0 | 2054 | 30.00% | 16.00% | 18.00% | 12.00% | 11.60% | 100.00% |
| isolation_forest | 57 / 0 | 2059 | 100.00% | 96.00% | 78.00% | 55.00% | 22.40% | 100.00% |

### 13

Operational population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 147 / 0 | 928 | 20.00% | 8.00% | 10.00% | 7.00% | 4.00% | 100.00% |
| errors | 147 / 0 | 928 | 100.00% | 100.00% | 100.00% | 100.00% | 56.40% | 100.00% |
| suspicious | 142 / 5 | 143 | 90.00% | 96.00% | 98.00% | 99.00% | 56.80% | 96.60% |
| support | 142 / 5 | 143 | 100.00% | 100.00% | 100.00% | 100.00% | 56.80% | 96.60% |
| weighted | 142 / 5 | 143 | 100.00% | 100.00% | 100.00% | 100.00% | 56.80% | 96.60% |
| share | 142 / 5 | 143 | 100.00% | 100.00% | 100.00% | 100.00% | 56.80% | 96.60% |
| statistics | 26 / 121 | 681 | 40.00% | 28.00% | 20.00% | 25.00% | 10.40% | 17.69% |
| group_sum | 26 / 121 | 681 | 20.00% | 16.00% | 10.00% | 7.00% | 9.20% | 17.69% |
| group_top2 | 26 / 121 | 681 | 20.00% | 28.00% | 22.00% | 19.00% | 9.60% | 17.69% |
| isolation_forest | 26 / 121 | 682 | 90.00% | 84.00% | 50.00% | 26.00% | 10.40% | 17.69% |

Matched population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 26 / 0 | 682 | 20.00% | 8.00% | 10.00% | 7.00% | 4.00% | 100.00% |
| errors | 26 / 0 | 682 | 100.00% | 80.00% | 44.00% | 22.00% | 8.80% | 100.00% |
| suspicious | 21 / 5 | 21 | 100.00% | 84.00% | 42.00% | 21.00% | 8.40% | 80.77% |
| support | 21 / 5 | 21 | 100.00% | 84.00% | 42.00% | 21.00% | 8.40% | 80.77% |
| weighted | 21 / 5 | 21 | 100.00% | 84.00% | 42.00% | 21.00% | 8.40% | 80.77% |
| share | 21 / 5 | 21 | 100.00% | 84.00% | 42.00% | 21.00% | 8.40% | 80.77% |
| statistics | 26 / 0 | 681 | 40.00% | 28.00% | 20.00% | 25.00% | 10.40% | 100.00% |
| group_sum | 26 / 0 | 681 | 20.00% | 16.00% | 10.00% | 7.00% | 9.20% | 100.00% |
| group_top2 | 26 / 0 | 681 | 20.00% | 28.00% | 22.00% | 19.00% | 9.60% | 100.00% |
| isolation_forest | 26 / 0 | 682 | 90.00% | 84.00% | 50.00% | 26.00% | 10.40% | 100.00% |

### 19

Operational population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 133 / 0 | 928 | 20.00% | 8.00% | 6.00% | 8.00% | 4.00% | 100.00% |
| errors | 133 / 0 | 928 | 100.00% | 100.00% | 100.00% | 100.00% | 51.20% | 100.00% |
| suspicious | 129 / 4 | 131 | 80.00% | 92.00% | 96.00% | 98.00% | 51.60% | 96.99% |
| support | 129 / 4 | 131 | 100.00% | 100.00% | 100.00% | 100.00% | 51.60% | 96.99% |
| weighted | 129 / 4 | 131 | 100.00% | 100.00% | 100.00% | 100.00% | 51.60% | 96.99% |
| share | 129 / 4 | 131 | 100.00% | 100.00% | 100.00% | 100.00% | 51.60% | 96.99% |
| statistics | 31 / 102 | 708 | 50.00% | 28.00% | 20.00% | 28.00% | 12.00% | 23.31% |
| group_sum | 31 / 102 | 708 | 40.00% | 20.00% | 10.00% | 6.00% | 10.40% | 23.31% |
| group_top2 | 31 / 102 | 708 | 30.00% | 28.00% | 20.00% | 20.00% | 11.60% | 23.31% |
| isolation_forest | 31 / 102 | 708 | 100.00% | 80.00% | 60.00% | 31.00% | 12.40% | 23.31% |

Matched population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 31 / 0 | 708 | 20.00% | 8.00% | 6.00% | 8.00% | 4.00% | 100.00% |
| errors | 31 / 0 | 708 | 100.00% | 100.00% | 54.00% | 28.00% | 11.20% | 100.00% |
| suspicious | 27 / 4 | 29 | 80.00% | 92.00% | 54.00% | 27.00% | 10.80% | 87.10% |
| support | 27 / 4 | 29 | 100.00% | 100.00% | 54.00% | 27.00% | 10.80% | 87.10% |
| weighted | 27 / 4 | 29 | 100.00% | 100.00% | 54.00% | 27.00% | 10.80% | 87.10% |
| share | 27 / 4 | 29 | 100.00% | 100.00% | 54.00% | 27.00% | 10.80% | 87.10% |
| statistics | 31 / 0 | 708 | 50.00% | 28.00% | 20.00% | 28.00% | 12.00% | 100.00% |
| group_sum | 31 / 0 | 708 | 40.00% | 20.00% | 10.00% | 6.00% | 10.40% | 100.00% |
| group_top2 | 31 / 0 | 708 | 30.00% | 28.00% | 20.00% | 20.00% | 11.60% | 100.00% |
| isolation_forest | 31 / 0 | 708 | 100.00% | 80.00% | 60.00% | 31.00% | 12.40% | 100.00% |

### 23

Operational population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 125 / 0 | 939 | 20.00% | 12.00% | 8.00% | 7.00% | 3.60% | 100.00% |
| errors | 125 / 0 | 939 | 100.00% | 100.00% | 100.00% | 100.00% | 48.00% | 100.00% |
| suspicious | 120 / 5 | 124 | 60.00% | 84.00% | 92.00% | 96.00% | 48.00% | 96.00% |
| support | 120 / 5 | 124 | 100.00% | 100.00% | 100.00% | 100.00% | 48.00% | 96.00% |
| weighted | 120 / 5 | 124 | 100.00% | 100.00% | 100.00% | 100.00% | 48.00% | 96.00% |
| share | 120 / 5 | 124 | 100.00% | 100.00% | 100.00% | 100.00% | 48.00% | 96.00% |
| statistics | 24 / 101 | 692 | 50.00% | 32.00% | 16.00% | 24.00% | 9.60% | 19.20% |
| group_sum | 24 / 101 | 692 | 40.00% | 24.00% | 12.00% | 8.00% | 8.40% | 19.20% |
| group_top2 | 24 / 101 | 692 | 50.00% | 28.00% | 18.00% | 19.00% | 9.20% | 19.20% |
| isolation_forest | 24 / 101 | 692 | 80.00% | 76.00% | 44.00% | 24.00% | 9.60% | 19.20% |

Matched population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 24 / 0 | 692 | 20.00% | 12.00% | 8.00% | 7.00% | 3.60% | 100.00% |
| errors | 24 / 0 | 692 | 100.00% | 84.00% | 42.00% | 21.00% | 8.40% | 100.00% |
| suspicious | 19 / 5 | 22 | 70.00% | 76.00% | 38.00% | 19.00% | 7.60% | 79.17% |
| support | 19 / 5 | 22 | 100.00% | 76.00% | 38.00% | 19.00% | 7.60% | 79.17% |
| weighted | 19 / 5 | 22 | 100.00% | 76.00% | 38.00% | 19.00% | 7.60% | 79.17% |
| share | 19 / 5 | 22 | 100.00% | 76.00% | 38.00% | 19.00% | 7.60% | 79.17% |
| statistics | 24 / 0 | 692 | 50.00% | 32.00% | 16.00% | 24.00% | 9.60% | 100.00% |
| group_sum | 24 / 0 | 692 | 40.00% | 24.00% | 12.00% | 8.00% | 8.40% | 100.00% |
| group_top2 | 24 / 0 | 692 | 50.00% | 28.00% | 18.00% | 19.00% | 9.20% | 100.00% |
| isolation_forest | 24 / 0 | 692 | 80.00% | 76.00% | 44.00% | 24.00% | 9.60% | 100.00% |

### 31

Operational population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 126 / 0 | 936 | 20.00% | 8.00% | 10.00% | 6.00% | 3.20% | 100.00% |
| errors | 126 / 0 | 936 | 100.00% | 100.00% | 100.00% | 100.00% | 48.00% | 100.00% |
| suspicious | 122 / 4 | 126 | 60.00% | 84.00% | 92.00% | 96.00% | 48.80% | 96.83% |
| support | 122 / 4 | 126 | 100.00% | 100.00% | 100.00% | 100.00% | 48.80% | 96.83% |
| weighted | 122 / 4 | 126 | 100.00% | 100.00% | 100.00% | 100.00% | 48.80% | 96.83% |
| share | 122 / 4 | 126 | 100.00% | 100.00% | 100.00% | 100.00% | 48.80% | 96.83% |
| statistics | 22 / 104 | 709 | 50.00% | 24.00% | 14.00% | 18.00% | 8.00% | 17.46% |
| group_sum | 22 / 104 | 709 | 20.00% | 16.00% | 8.00% | 5.00% | 7.60% | 17.46% |
| group_top2 | 22 / 104 | 709 | 40.00% | 24.00% | 18.00% | 13.00% | 8.00% | 17.46% |
| isolation_forest | 22 / 104 | 711 | 70.00% | 72.00% | 40.00% | 21.00% | 8.80% | 17.46% |

Matched population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 22 / 0 | 711 | 20.00% | 8.00% | 10.00% | 6.00% | 3.20% | 100.00% |
| errors | 22 / 0 | 711 | 100.00% | 68.00% | 36.00% | 18.00% | 7.20% | 100.00% |
| suspicious | 18 / 4 | 22 | 60.00% | 72.00% | 36.00% | 18.00% | 7.20% | 81.82% |
| support | 18 / 4 | 22 | 100.00% | 72.00% | 36.00% | 18.00% | 7.20% | 81.82% |
| weighted | 18 / 4 | 22 | 100.00% | 72.00% | 36.00% | 18.00% | 7.20% | 81.82% |
| share | 18 / 4 | 22 | 100.00% | 72.00% | 36.00% | 18.00% | 7.20% | 81.82% |
| statistics | 22 / 0 | 709 | 50.00% | 24.00% | 14.00% | 18.00% | 8.00% | 100.00% |
| group_sum | 22 / 0 | 709 | 20.00% | 16.00% | 8.00% | 5.00% | 7.60% | 100.00% |
| group_top2 | 22 / 0 | 709 | 40.00% | 24.00% | 18.00% | 13.00% | 8.00% | 100.00% |
| isolation_forest | 22 / 0 | 711 | 70.00% | 72.00% | 40.00% | 21.00% | 8.80% | 100.00% |

### 41

Operational population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 135 / 0 | 954 | 20.00% | 8.00% | 6.00% | 6.00% | 3.60% | 100.00% |
| errors | 135 / 0 | 954 | 100.00% | 100.00% | 100.00% | 100.00% | 52.40% | 100.00% |
| suspicious | 132 / 3 | 138 | 40.00% | 76.00% | 88.00% | 94.00% | 52.80% | 97.78% |
| support | 132 / 3 | 138 | 100.00% | 100.00% | 100.00% | 100.00% | 52.80% | 97.78% |
| weighted | 132 / 3 | 138 | 100.00% | 100.00% | 100.00% | 100.00% | 52.80% | 97.78% |
| share | 132 / 3 | 138 | 100.00% | 100.00% | 100.00% | 100.00% | 52.80% | 97.78% |
| statistics | 21 / 114 | 703 | 50.00% | 28.00% | 24.00% | 18.00% | 8.40% | 15.56% |
| group_sum | 21 / 114 | 703 | 20.00% | 16.00% | 8.00% | 7.00% | 7.20% | 15.56% |
| group_top2 | 21 / 114 | 703 | 40.00% | 28.00% | 20.00% | 14.00% | 8.00% | 15.56% |
| isolation_forest | 21 / 114 | 706 | 90.00% | 72.00% | 40.00% | 21.00% | 8.40% | 15.56% |

Matched population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 21 / 0 | 706 | 20.00% | 8.00% | 6.00% | 6.00% | 3.60% | 100.00% |
| errors | 21 / 0 | 706 | 100.00% | 68.00% | 38.00% | 19.00% | 7.60% | 100.00% |
| suspicious | 18 / 3 | 23 | 50.00% | 72.00% | 36.00% | 18.00% | 7.20% | 85.71% |
| support | 18 / 3 | 23 | 100.00% | 72.00% | 36.00% | 18.00% | 7.20% | 85.71% |
| weighted | 18 / 3 | 23 | 100.00% | 72.00% | 36.00% | 18.00% | 7.20% | 85.71% |
| share | 18 / 3 | 23 | 100.00% | 72.00% | 36.00% | 18.00% | 7.20% | 85.71% |
| statistics | 21 / 0 | 703 | 50.00% | 28.00% | 24.00% | 18.00% | 8.40% | 100.00% |
| group_sum | 21 / 0 | 703 | 20.00% | 16.00% | 8.00% | 7.00% | 7.20% | 100.00% |
| group_top2 | 21 / 0 | 703 | 40.00% | 28.00% | 20.00% | 14.00% | 8.00% | 100.00% |
| isolation_forest | 21 / 0 | 706 | 90.00% | 72.00% | 40.00% | 21.00% | 8.40% | 100.00% |

### 53

Operational population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 132 / 0 | 970 | 20.00% | 12.00% | 10.00% | 7.00% | 4.00% | 100.00% |
| errors | 132 / 0 | 970 | 100.00% | 100.00% | 100.00% | 100.00% | 50.80% | 100.00% |
| suspicious | 128 / 4 | 133 | 50.00% | 80.00% | 90.00% | 95.00% | 51.20% | 96.97% |
| support | 128 / 4 | 133 | 100.00% | 100.00% | 100.00% | 100.00% | 51.20% | 96.97% |
| weighted | 128 / 4 | 133 | 100.00% | 100.00% | 100.00% | 100.00% | 51.20% | 96.97% |
| share | 128 / 4 | 133 | 100.00% | 100.00% | 100.00% | 100.00% | 51.20% | 96.97% |
| statistics | 25 / 107 | 723 | 40.00% | 28.00% | 18.00% | 22.00% | 9.60% | 18.94% |
| group_sum | 25 / 107 | 723 | 20.00% | 16.00% | 10.00% | 7.00% | 7.60% | 18.94% |
| group_top2 | 25 / 107 | 723 | 50.00% | 28.00% | 18.00% | 12.00% | 8.80% | 18.94% |
| isolation_forest | 25 / 107 | 727 | 70.00% | 80.00% | 48.00% | 24.00% | 10.00% | 18.94% |

Matched population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 25 / 0 | 727 | 20.00% | 12.00% | 10.00% | 7.00% | 4.00% | 100.00% |
| errors | 25 / 0 | 727 | 100.00% | 80.00% | 44.00% | 22.00% | 8.80% | 100.00% |
| suspicious | 21 / 4 | 26 | 50.00% | 80.00% | 42.00% | 21.00% | 8.40% | 84.00% |
| support | 21 / 4 | 26 | 100.00% | 84.00% | 42.00% | 21.00% | 8.40% | 84.00% |
| weighted | 21 / 4 | 26 | 100.00% | 84.00% | 42.00% | 21.00% | 8.40% | 84.00% |
| share | 21 / 4 | 26 | 100.00% | 84.00% | 42.00% | 21.00% | 8.40% | 84.00% |
| statistics | 25 / 0 | 723 | 40.00% | 28.00% | 18.00% | 22.00% | 9.60% | 100.00% |
| group_sum | 25 / 0 | 723 | 20.00% | 16.00% | 10.00% | 7.00% | 7.60% | 100.00% |
| group_top2 | 25 / 0 | 723 | 50.00% | 28.00% | 18.00% | 12.00% | 8.80% | 100.00% |
| isolation_forest | 25 / 0 | 727 | 70.00% | 80.00% | 48.00% | 24.00% | 10.00% | 100.00% |

### 67

Operational population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 129 / 0 | 936 | 20.00% | 8.00% | 8.00% | 7.00% | 3.20% | 100.00% |
| errors | 129 / 0 | 936 | 100.00% | 100.00% | 100.00% | 100.00% | 49.20% | 100.00% |
| suspicious | 124 / 5 | 127 | 70.00% | 88.00% | 94.00% | 97.00% | 49.60% | 96.12% |
| support | 124 / 5 | 127 | 100.00% | 100.00% | 100.00% | 100.00% | 49.60% | 96.12% |
| weighted | 124 / 5 | 127 | 100.00% | 100.00% | 100.00% | 100.00% | 49.60% | 96.12% |
| share | 124 / 5 | 127 | 100.00% | 100.00% | 100.00% | 100.00% | 49.60% | 96.12% |
| statistics | 24 / 105 | 694 | 50.00% | 24.00% | 16.00% | 21.00% | 8.80% | 18.60% |
| group_sum | 24 / 105 | 694 | 20.00% | 16.00% | 10.00% | 8.00% | 8.40% | 18.60% |
| group_top2 | 24 / 105 | 694 | 40.00% | 24.00% | 24.00% | 17.00% | 8.80% | 18.60% |
| isolation_forest | 24 / 105 | 696 | 70.00% | 76.00% | 44.00% | 22.00% | 9.60% | 18.60% |

Matched population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 24 / 0 | 696 | 20.00% | 8.00% | 8.00% | 7.00% | 3.20% | 100.00% |
| errors | 24 / 0 | 696 | 100.00% | 72.00% | 40.00% | 20.00% | 8.00% | 100.00% |
| suspicious | 19 / 5 | 22 | 70.00% | 76.00% | 38.00% | 19.00% | 7.60% | 79.17% |
| support | 19 / 5 | 22 | 100.00% | 76.00% | 38.00% | 19.00% | 7.60% | 79.17% |
| weighted | 19 / 5 | 22 | 100.00% | 76.00% | 38.00% | 19.00% | 7.60% | 79.17% |
| share | 19 / 5 | 22 | 100.00% | 76.00% | 38.00% | 19.00% | 7.60% | 79.17% |
| statistics | 24 / 0 | 694 | 50.00% | 24.00% | 16.00% | 21.00% | 8.80% | 100.00% |
| group_sum | 24 / 0 | 694 | 20.00% | 16.00% | 10.00% | 8.00% | 8.40% | 100.00% |
| group_top2 | 24 / 0 | 694 | 40.00% | 24.00% | 24.00% | 17.00% | 8.80% | 100.00% |
| isolation_forest | 24 / 0 | 696 | 70.00% | 76.00% | 44.00% | 22.00% | 9.60% | 100.00% |

### 71

Operational population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 135 / 0 | 966 | 20.00% | 8.00% | 8.00% | 8.00% | 3.20% | 100.00% |
| errors | 135 / 0 | 966 | 100.00% | 100.00% | 100.00% | 100.00% | 52.40% | 100.00% |
| suspicious | 131 / 4 | 132 | 90.00% | 96.00% | 98.00% | 99.00% | 52.40% | 97.04% |
| support | 131 / 4 | 132 | 100.00% | 100.00% | 100.00% | 100.00% | 52.40% | 97.04% |
| weighted | 131 / 4 | 132 | 100.00% | 100.00% | 100.00% | 100.00% | 52.40% | 97.04% |
| share | 131 / 4 | 132 | 100.00% | 100.00% | 100.00% | 100.00% | 52.40% | 97.04% |
| statistics | 20 / 115 | 712 | 50.00% | 28.00% | 32.00% | 18.00% | 7.60% | 14.81% |
| group_sum | 20 / 115 | 712 | 20.00% | 20.00% | 12.00% | 7.00% | 6.80% | 14.81% |
| group_top2 | 20 / 115 | 712 | 50.00% | 28.00% | 26.00% | 14.00% | 7.60% | 14.81% |
| isolation_forest | 20 / 115 | 713 | 90.00% | 72.00% | 38.00% | 20.00% | 8.00% | 14.81% |

Matched population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 20 / 0 | 713 | 20.00% | 8.00% | 8.00% | 8.00% | 3.20% | 100.00% |
| errors | 20 / 0 | 713 | 100.00% | 60.00% | 36.00% | 18.00% | 7.20% | 100.00% |
| suspicious | 16 / 4 | 17 | 90.00% | 64.00% | 32.00% | 16.00% | 6.40% | 80.00% |
| support | 16 / 4 | 17 | 100.00% | 64.00% | 32.00% | 16.00% | 6.40% | 80.00% |
| weighted | 16 / 4 | 17 | 100.00% | 64.00% | 32.00% | 16.00% | 6.40% | 80.00% |
| share | 16 / 4 | 17 | 100.00% | 64.00% | 32.00% | 16.00% | 6.40% | 80.00% |
| statistics | 20 / 0 | 712 | 50.00% | 28.00% | 32.00% | 18.00% | 7.60% | 100.00% |
| group_sum | 20 / 0 | 712 | 20.00% | 20.00% | 12.00% | 7.00% | 6.80% | 100.00% |
| group_top2 | 20 / 0 | 712 | 50.00% | 28.00% | 26.00% | 14.00% | 7.60% | 100.00% |
| isolation_forest | 20 / 0 | 713 | 90.00% | 72.00% | 38.00% | 20.00% | 8.00% | 100.00% |

### broken-links

Operational population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 0 / 0 | 1510 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| errors | 0 / 0 | 1510 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| suspicious | 0 / 0 | 0 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| support | 0 / 0 | 0 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| weighted | 0 / 0 | 0 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| share | 0 / 0 | 0 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| statistics | 0 / 0 | 346 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| group_sum | 0 / 0 | 346 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| group_top2 | 0 / 0 | 346 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| isolation_forest | 0 / 0 | 348 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |

Matched population:

| Method | Eligible / excluded positive IPs | Returned | Yield 10 | 25 | 50 | 100 | 250 | Full recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| requests | 0 / 0 | 348 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| errors | 0 / 0 | 348 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| suspicious | 0 / 0 | 0 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| support | 0 / 0 | 0 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| weighted | 0 / 0 | 0 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| share | 0 / 0 | 0 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| statistics | 0 / 0 | 346 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| group_sum | 0 / 0 | 346 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| group_top2 | 0 / 0 | 346 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |
| isolation_forest | 0 / 0 | 348 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | n/a |

## Benign broken links

No attack recall is defined for this case. The suspicious queue returned no clients, so there are no supporting hostile detections or source references to report. The other orderings' returned false-recommendation IPs are preserved in broken-links.json.gz; those entries do not contain supporting detection references. Counts below describe reviewed non-relevant clients, not attack discoveries.

| Method | Returned | False recommendations at 10 / 25 / 50 / 100 / 250 |
|---|---:|---:|
| requests | 1510 | 10 / 25 / 50 / 100 / 250 |
| errors | 1510 | 10 / 25 / 50 / 100 / 250 |
| suspicious | 0 | 0 / 0 / 0 / 0 / 0 |
| support | 0 | 0 / 0 / 0 / 0 / 0 |
| weighted | 0 | 0 / 0 / 0 / 0 / 0 |
| share | 0 | 0 / 0 / 0 / 0 / 0 |
| statistics | 346 | 10 / 25 / 50 / 100 / 250 |
| group_sum | 346 | 10 / 25 / 50 / 100 / 250 |
| group_top2 | 346 | 10 / 25 / 50 / 100 / 250 |
| isolation_forest | 348 | 10 / 25 / 50 / 100 / 250 |

## Unusualness tie audit

A ceiling tie on one feature does not prove that the complete ranking vectors tie. IP-dependent positions below count displayed positions in tied complete-vector groups; a boundary tie means membership of that prefix depends on the final IP tie-break.

| Case | Complete-vector tie groups | Largest group | IP-dependent positions 10 / 25 / 50 / 100 / 250 | Boundary ties at those budgets | Ceiling counts: distinct paths / concentration / 4xx / 5xx |
|---|---:|---:|---:|---|---|
| medium | 201 | 10 | 0 / 0 / 0 / 10 / 54 | 0 / 0 / 0 / 0 / 0 | 13 / 1 / 45 / 0 |
| 13 | 48 | 4 | 0 / 0 / 4 / 14 / 50 | 0 / 0 / 0 / 0 / 0 | 8 / 1 / 14 / 0 |
| 19 | 62 | 4 | 0 / 0 / 5 / 21 / 53 | 0 / 0 / 0 / 0 / 0 | 9 / 1 / 19 / 0 |
| 23 | 61 | 9 | 0 / 0 / 6 / 17 / 46 | 0 / 0 / 0 / 1 / 0 | 8 / 1 / 13 / 0 |
| 31 | 52 | 5 | 0 / 0 / 7 / 17 / 40 | 0 / 0 / 0 / 0 / 0 | 7 / 1 / 12 / 0 |
| 41 | 54 | 5 | 0 / 0 / 4 / 17 / 41 | 0 / 0 / 0 / 0 / 0 | 7 / 1 / 11 / 0 |
| 53 | 58 | 5 | 0 / 0 / 4 / 15 / 52 | 0 / 0 / 0 / 0 / 0 | 7 / 1 / 14 / 0 |
| 67 | 54 | 4 | 0 / 0 / 4 / 6 / 35 | 0 / 0 / 0 / 0 / 0 | 3 / 1 / 13 / 0 |
| 71 | 56 | 5 | 0 / 0 / 6 / 14 / 43 | 0 / 0 / 0 / 0 / 0 | 6 / 1 / 9 / 0 |
| broken-links | 19 | 4 | 0 / 2 / 2 / 11 / 23 | 0 / 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| mixed | 17 | 2 | 0 / 0 / 4 / 20 / 34 | 0 / 0 / 0 / 0 / 0 | 20 / 0 / 10 / 0 |
| isolated | 17 | 2 | 0 / 0 / 4 / 20 / 34 | 0 / 0 / 0 / 0 / 0 | 20 / 0 / 10 / 0 |
| moderate | 17 | 2 | 0 / 0 / 4 / 20 / 34 | 0 / 0 / 0 / 0 / 0 | 20 / 0 / 10 / 0 |
| uniform | 0 | 0 | 0 / 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| attack-heavy | 16 | 3 | 0 / 0 / 6 / 27 / 33 | 0 / 0 / 0 / 0 / 0 | 10 / 90 / 100 / 0 |

## Independent controlled unusualness judgments

Five source-backed workloads contain 132 clients each: mixed legitimate roles, isolated extreme transfer, several moderate deviations, uniform traffic, and an attack-heavy population (90 routine injection clients). Mixed roles include routine crawlers, shared addresses, benign 404s and missing paths/statuses/sizes. Investigation positives are the preassigned isolated-extreme and several-moderate-deviations roles. Routine attacks in the attack-heavy scenario are not unusualness positives. Missing data stays unavailable; comparable feature counts are recorded in every audit.

The grouped alternatives use the maximum upper-tail deviation within volume, rate, target-shape and response groups. They sum all four groups or only the strongest two. Equal aggregate scores use sorted group deviations and then IP. The GUI keeps lexicographic statistics: these constructed scenarios establish mechanics and tradeoffs, not representative unusualness accuracy.

| Scenario | Positives | Method | Found at 10 / 25 / 50 | Recall at 10 |
|---|---:|---|---|---:|
| mixed | 2 | statistics | 2 / 2 / 2 | 100.00% |
| mixed | 2 | group_sum | 2 / 2 / 2 | 100.00% |
| mixed | 2 | group_top2 | 2 / 2 / 2 | 100.00% |
| mixed | 2 | isolation_forest | 2 / 2 / 2 | 100.00% |
| isolated | 1 | statistics | 1 / 1 / 1 | 100.00% |
| isolated | 1 | group_sum | 1 / 1 / 1 | 100.00% |
| isolated | 1 | group_top2 | 1 / 1 / 1 | 100.00% |
| isolated | 1 | isolation_forest | 1 / 1 / 1 | 100.00% |
| moderate | 1 | statistics | 1 / 1 / 1 | 100.00% |
| moderate | 1 | group_sum | 1 / 1 / 1 | 100.00% |
| moderate | 1 | group_top2 | 1 / 1 / 1 | 100.00% |
| moderate | 1 | isolation_forest | 1 / 1 / 1 | 100.00% |
| uniform | 0 | statistics | 0 / 0 / 0 | n/a |
| uniform | 0 | group_sum | 0 / 0 / 0 | n/a |
| uniform | 0 | group_top2 | 0 / 0 / 0 | n/a |
| uniform | 0 | isolation_forest | no varying features | n/a |
| attack-heavy | 2 | statistics | 2 / 2 / 2 | 100.00% |
| attack-heavy | 2 | group_sum | 2 / 2 / 2 | 100.00% |
| attack-heavy | 2 | group_top2 | 2 / 2 / 2 | 100.00% |
| attack-heavy | 2 | isolation_forest | 2 / 2 / 2 | 100.00% |

The nonuniform scenarios retrieve all one or two planted positives within ten for the four primary orderings. This remains an easy constructed test and does not close the real unusualness-validation gap. Uniform traffic produces no statistical recommendations and no varying model features; recall is undefined because there are no positives.

## Model-seed variation

Ranges show min/max yield across all five predeclared seeds, with seed 42 shown separately. No seed was selected for its result.

| Case | Cohort | Yield 10 range (seed 42) | Yield 25 range (seed 42) | Yield 50 range (seed 42) |
|---|---|---:|---:|---:|
| medium | operational | 100.00% to 100.00% (100.00%) | 72.00% to 96.00% (96.00%) | 70.00% to 80.00% (78.00%) |
| medium | matched | 100.00% to 100.00% (100.00%) | 72.00% to 96.00% (96.00%) | 70.00% to 80.00% (78.00%) |
| 13 | operational | 80.00% to 90.00% (90.00%) | 80.00% to 84.00% (84.00%) | 48.00% to 50.00% (50.00%) |
| 13 | matched | 80.00% to 90.00% (90.00%) | 80.00% to 84.00% (84.00%) | 48.00% to 50.00% (50.00%) |
| 19 | operational | 80.00% to 100.00% (100.00%) | 76.00% to 84.00% (80.00%) | 58.00% to 60.00% (60.00%) |
| 19 | matched | 80.00% to 100.00% (100.00%) | 76.00% to 84.00% (80.00%) | 58.00% to 60.00% (60.00%) |
| 23 | operational | 80.00% to 90.00% (80.00%) | 76.00% to 76.00% (76.00%) | 44.00% to 48.00% (44.00%) |
| 23 | matched | 80.00% to 90.00% (80.00%) | 76.00% to 76.00% (76.00%) | 44.00% to 48.00% (44.00%) |
| 31 | operational | 70.00% to 80.00% (70.00%) | 72.00% to 72.00% (72.00%) | 40.00% to 40.00% (40.00%) |
| 31 | matched | 70.00% to 80.00% (70.00%) | 72.00% to 72.00% (72.00%) | 40.00% to 40.00% (40.00%) |
| 41 | operational | 90.00% to 100.00% (90.00%) | 72.00% to 76.00% (72.00%) | 38.00% to 40.00% (40.00%) |
| 41 | matched | 90.00% to 100.00% (90.00%) | 72.00% to 76.00% (72.00%) | 38.00% to 40.00% (40.00%) |
| 53 | operational | 70.00% to 80.00% (70.00%) | 76.00% to 84.00% (80.00%) | 48.00% to 48.00% (48.00%) |
| 53 | matched | 70.00% to 80.00% (70.00%) | 76.00% to 84.00% (80.00%) | 48.00% to 48.00% (48.00%) |
| 67 | operational | 70.00% to 80.00% (70.00%) | 76.00% to 76.00% (76.00%) | 42.00% to 44.00% (44.00%) |
| 67 | matched | 70.00% to 80.00% (70.00%) | 76.00% to 76.00% (76.00%) | 42.00% to 44.00% (44.00%) |
| 71 | operational | 90.00% to 100.00% (90.00%) | 68.00% to 72.00% (72.00%) | 36.00% to 38.00% (38.00%) |
| 71 | matched | 90.00% to 100.00% (90.00%) | 68.00% to 72.00% (72.00%) | 36.00% to 38.00% (38.00%) |
| broken-links | operational | 0.00% to 0.00% (0.00%) | 0.00% to 0.00% (0.00%) | 0.00% to 0.00% (0.00%) |
| broken-links | matched | 0.00% to 0.00% (0.00%) | 0.00% to 0.00% (0.00%) | 0.00% to 0.00% (0.00%) |
| mixed | operational | 20.00% to 20.00% (20.00%) | 8.00% to 8.00% (8.00%) | 4.00% to 4.00% (4.00%) |
| mixed | matched | 20.00% to 20.00% (20.00%) | 8.00% to 8.00% (8.00%) | 4.00% to 4.00% (4.00%) |
| isolated | operational | 10.00% to 10.00% (10.00%) | 4.00% to 4.00% (4.00%) | 2.00% to 2.00% (2.00%) |
| isolated | matched | 10.00% to 10.00% (10.00%) | 4.00% to 4.00% (4.00%) | 2.00% to 2.00% (2.00%) |
| moderate | operational | 10.00% to 10.00% (10.00%) | 4.00% to 4.00% (4.00%) | 2.00% to 2.00% (2.00%) |
| moderate | matched | 10.00% to 10.00% (10.00%) | 4.00% to 4.00% (4.00%) | 2.00% to 2.00% (2.00%) |
| uniform | operational | unavailable | unavailable | unavailable |
| uniform | matched | unavailable | unavailable | unavailable |
| attack-heavy | operational | 20.00% to 20.00% (20.00%) | 8.00% to 8.00% (8.00%) | 4.00% to 4.00% (4.00%) |
| attack-heavy | matched | 20.00% to 20.00% (20.00%) | 8.00% to 8.00% (8.00%) | 4.00% to 4.00% (4.00%) |

## Provenance and machine-readable results

For the ten corpus records, source hashes were checked against their manifests and every parsed line was matched to a unique truth line and IP. Controlled workloads instead use source-hash checks and embedded per-IP judgments assigned from generator roles before ranking; their fixture hashes identify that generator. Each compressed JSON preserves full curves and metadata. frozen-selection.json binds the development artifacts, inputs and pre-promotion code hashes; promotion.json records the unchanged gate and per-case metrics. It is an archival experiment fingerprint, so the runner rejects resuming it after a policy or source change.

| Case | Requests | CRS revision | CRS configuration fingerprint | Raw record |
|---|---:|---|---|---|
| medium | 243908 | d694d465951ee06347214f1291ae096e40700001 | f357d142fbcc4441 | [medium.json.gz](triage-validation/medium.json.gz) |
| 13 | 66531 | d694d465951ee06347214f1291ae096e40700001 | f357d142fbcc4441 | [13.json.gz](triage-validation/13.json.gz) |
| 19 | 67143 | d694d465951ee06347214f1291ae096e40700001 | f357d142fbcc4441 | [19.json.gz](triage-validation/19.json.gz) |
| 23 | 67144 | d694d465951ee06347214f1291ae096e40700001 | f357d142fbcc4441 | [23.json.gz](triage-validation/23.json.gz) |
| 31 | 67052 | d694d465951ee06347214f1291ae096e40700001 | f357d142fbcc4441 | [31.json.gz](triage-validation/31.json.gz) |
| 41 | 66451 | d694d465951ee06347214f1291ae096e40700001 | f357d142fbcc4441 | [41.json.gz](triage-validation/41.json.gz) |
| 53 | 67722 | d694d465951ee06347214f1291ae096e40700001 | f357d142fbcc4441 | [53.json.gz](triage-validation/53.json.gz) |
| 67 | 66300 | d694d465951ee06347214f1291ae096e40700001 | f357d142fbcc4441 | [67.json.gz](triage-validation/67.json.gz) |
| 71 | 66464 | d694d465951ee06347214f1291ae096e40700001 | f357d142fbcc4441 | [71.json.gz](triage-validation/71.json.gz) |
| broken-links | 20000 | d694d465951ee06347214f1291ae096e40700001 | f357d142fbcc4441 | [broken-links.json.gz](triage-validation/broken-links.json.gz) |
| controlled-mixed | 14148 | d694d465951ee06347214f1291ae096e40700001 | d1c9e04591ad1e66 | [record](triage-validation/controlled-mixed.json.gz) |
| controlled-isolated | 14008 | d694d465951ee06347214f1291ae096e40700001 | d1c9e04591ad1e66 | [record](triage-validation/controlled-isolated.json.gz) |
| controlled-moderate | 14148 | d694d465951ee06347214f1291ae096e40700001 | d1c9e04591ad1e66 | [record](triage-validation/controlled-moderate.json.gz) |
| controlled-uniform | 7920 | d694d465951ee06347214f1291ae096e40700001 | d1c9e04591ad1e66 | [record](triage-validation/controlled-uniform.json.gz) |
| controlled-attack-heavy | 12748 | d694d465951ee06347214f1291ae096e40700001 | d1c9e04591ad1e66 | [record](triage-validation/controlled-attack-heavy.json.gz) |

The corpus records store source, truth and CRS content SHA-256 values. Controlled records store source, fixture and CRS hashes, embedded judgments and scenario roles. All records state judgment purpose; all configurations above use paranoia level 2. No detection rules were changed for the experiment.

## Responsiveness and scan cost

On the existing 243,908-request medium case (2,760 clients, largest client
16,860 requests), a hidden native Windows MainWindow produced the first usable
All clients results 0.706 seconds after opening. This met the one-second target.
Fifteen searches during a cold policy-3 scan took 0.185 to 0.211 seconds including
the 150 ms input debounce. The filesystem was warm from prior evaluations.

The scan took 117.78 seconds; opening through completed recommendations took
119.24 seconds. Worker OS peak working set was 307,417,088 bytes (293.2 MiB).
Reopening the completed derived index took 0.183 seconds. A 20 ms GUI timer had
a 20.62 ms p95 gap and 409.58 ms maximum gap, including case opening. The full test run
overlapped this measurement, so the scan duration is not an isolated comparison
with the earlier 102.39-second run. Full-population search no longer waits for
that scan, but the scan cost itself remains a limitation for larger cases.

These observations measure this machine and case, not a general latency or
memory guarantee. The scan process did not load truth or fit a model. Its memory
depends on the largest client and the compact case-wide profile collection.
Raw timer and search measurements are in
[performance.json](triage-validation/performance.json).
The clean run used a fresh copy of the same case without derived caches.
The initial probe recorded 0.525-second first results and a 117.06-second scan,
then exited nonzero during measurement teardown. Those observations remain in
[performance-initial.json](triage-validation/performance-initial.json). Explicitly
draining GUI worker jobs fixed the harness teardown; both the cached repeat and
the fresh-copy cold repeat exited successfully.

## Delivery verification

### Review corrections

The selection discussion now reports the ceiling ties explicitly. Production
ranking and the share experiment call the same priority-score function; the
formula, tiebreaks, policy version and frozen choice are unchanged.

An abandoned direct evaluation scan directory, `small-s23/triage/scan-0cw97vup`,
contained a 1,437,696-byte CRS index and an empty DuckDB directory. It was removed
after confirming no evaluation or scan process remained. Its location matches a
direct scan rather than the GUI's parent-owned `worker-*/scan-*` layout; the
directory alone does not establish exactly how the process stopped.

Regression tests cover a Python interrupt during a direct scan and abrupt exit
of a real scanning child under the GUI supervisor. Both preserve the previous
completed cache and remove scratch files. Deliberately disabling each cleanup
path makes the corresponding test fail. Existing tests also cover forced
cancellation of an unresponsive child. Cleanup still depends on a live parent
and successful filesystem removal. Abrupt termination of a direct scan or its
supervising parent can bypass cleanup; this is not an orphan-recovery feature.

After these corrections, the full suite passed in 357 seconds. Lint, formatting
and both platform type checks passed. An independent read-only review confirmed
the measurements and shared formula; its test-hardening suggestions were applied
and received a clean recheck. The staged rebuild took 53 seconds and verified
native Qt loading before installing the 251 MB bundle. The packaged application
completed a fresh 33-client scan with two progress updates. Its GUI again found
population position 501 and opened reconstruction while scanning was deliberately
blocked, then followed a suspicious reason to matching source evidence. Both
packaged probes exited successfully. No commit, merge or push was performed.

### Original implementation checks

The full repository suite passed in 380 seconds. Lint, formatting and both
Windows and Linux target type checks passed. Two implementation reviews and a
fresh final audit were read-only; the implementation applied their fixes and
received clean rechecks. The full suite also caught a returned time-range guard
regression, which was corrected before the successful build.

The staged packaging workflow rebuilt and swapped in the 251 MB Windows GUI.
It verified bundled rules, version metadata, absence of QtWebEngine and native
Qt runtime imports. The packaged executable completed a fresh 33-client
background scan with two progress updates. A separate packaged GUI probe found
population position 501 while its scanner was deliberately blocked, opened
ordinary reconstruction before releasing the scan, then followed a suspicious
reason into reconstruction and verified matching source evidence on screen.
The probe exited successfully; its record is
[packaged-gui.json](triage-validation/packaged-gui.json).

The build contains the working-tree implementation. No commit, merge or remote
publication was performed.
