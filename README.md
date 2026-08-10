# Zero-Day Threat Fingerprinting Platform

A multi-page AI-driven network intrusion triage platform built on the
**NSL-KDD** benchmark dataset — not just a classifier demo, but a full
mini-product with live model analytics, MITRE ATT&CK mapping, and an
interactive triage console.

## Pages

1. **Home** — problem statement, architecture, project pitch
2. **🛡️ Live Triage Console** — upload traffic CSV, get per-row verdicts,
   charts, and downloadable results. Five distinct sample CSVs available
   in the sidebar (Normal / DoS / Probe / rare R2L-U2R / mixed).
3. **📊 Model Insights** — live confusion matrix, per-class precision/recall,
   feature importance, and anomaly-detector flag rates, all computed on
   demand from a labeled holdout set the models never trained on.
4. **🧬 MITRE ATT&CK Mapping** — explains how each verdict maps to a
   real-world adversary tactic.
5. **📈 Evaluation** — live, computed comparison of the two-layer pipeline
   against the classifier alone (attack catch rate + false-positive rate),
   plus a compact architecture/tech-stack reference table

## How it works (the core idea)

1. **Known-attack classifier** (Random Forest) — scores traffic against
   Normal / DoS / Probe / R2L / U2R.
2. **Anomaly detector** (Isolation Forest, trained only on normal traffic) —
   flags statistically unusual traffic independent of the classifier.
3. **Fingerprinting** — traffic the classifier isn't confident about, but the
   anomaly detector flags, gets compared against the centroid of each known
   attack family in scaled feature space. The closest match is reported as a
   **hypothesis** ("resembles Probe"), not a certainty — this is the
   zero-day-handling piece that goes beyond a standard classifier.

## Running locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

Open the printed local URL (usually `http://localhost:8501`). Use the
sidebar to navigate between pages. On the Live Triage Console page, grab
any of the 5 sample CSVs and upload it back in to see the full pipeline run.

## Deploying it publicly (for your submission link)

1. Push this **entire folder** (including the `pages/`, `data/`, and
   `.streamlit/` subfolders — all of it) to a GitHub repo, preserving the
   folder structure exactly.
2. Go to [share.streamlit.io](https://share.streamlit.io) → sign in with
   GitHub → **Create app** → point it at your repo, main file `app.py`.
3. Deploy. You'll get a public URL like `https://your-app.streamlit.app`.

**Important:** Streamlit's multi-page feature requires the `pages/` folder
to sit in the same directory as `app.py` with its filenames intact — don't
rename or flatten the folder structure when uploading. (Page filenames are
plain ASCII on purpose — emoji in filenames can get corrupted by some
zip tools/OSes and show up as garbled characters in the sidebar. The emoji
you see in the app itself are in the page *titles*, not the filenames, so
they always render correctly regardless of platform.)

## Honest note on model performance

NSL-KDD's test set intentionally includes attack subtypes never seen during
training — a well-documented, deliberate property of the dataset that makes
it a genuinely hard benchmark. R2L and U2R are the hardest categories (rare
in training, and behave statistically like normal traffic). The Model
Insights page shows this transparently via a live confusion matrix rather
than hiding it — and it's a good talking point in a demo: it's exactly the
scenario the anomaly-detection + fingerprinting layer exists to handle.

Note: the accuracy shown on the Model Insights page uses a **class-balanced**
holdout set (roughly equal rows per category) so rare attack types are
visible in the confusion matrix — this will read differently from a
natural-distribution accuracy number, which is normal and expected.

## Files

```
app.py                          # Home page
core.py                         # shared model-loading + triage logic
requirements.txt
.streamlit/config.toml          # dark theme
known_attack_classifier.pkl     # trained Random Forest pipeline
anomaly_detector.pkl            # trained Isolation Forest pipeline
pages/
  1_Live_Triage_Console.py
  2_Model_Insights.py
  3_MITRE_Mapping.py
  4_Evaluation.py
data/
  train_clean_app.csv           # reference data for scaler/centroids
  eval_holdout.csv              # labeled holdout for Model Insights
  demo_normal_traffic.csv
  demo_dos_attack.csv
  demo_probe_attack.csv
  demo_rare_r2l_u2r.csv
  demo_mixed_traffic.csv
```
