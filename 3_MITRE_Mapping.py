import streamlit as st
import pandas as pd
from core import inject_base_css

st.set_page_config(page_title="MITRE ATT&CK Mapping", page_icon="🧬", layout="wide")
inject_base_css()

st.title("🧬 MITRE ATT&CK Mapping")
st.caption("Translating raw ML verdicts into language a SOC analyst already understands.")

st.markdown(
    """
    Every verdict from the triage console is mapped to a tactic in the
    [MITRE ATT&CK](https://attack.mitre.org/) framework — the industry-standard
    knowledge base of adversary behavior. This turns a bare classifier label
    like `"DoS"` into something an analyst can act on immediately.
    """
)

mapping = pd.DataFrame([
    {"NSL-KDD Category": "DoS", "MITRE Tactic": "Impact",
     "What it means": "Adversary is degrading or disrupting availability of a system or service."},
    {"NSL-KDD Category": "Probe", "MITRE Tactic": "Reconnaissance",
     "What it means": "Adversary is gathering information to plan future operations (e.g. port/service scanning)."},
    {"NSL-KDD Category": "R2L", "MITRE Tactic": "Initial Access",
     "What it means": "Adversary is attempting to gain an initial foothold from a remote position."},
    {"NSL-KDD Category": "U2R", "MITRE Tactic": "Privilege Escalation",
     "What it means": "Adversary already has some access and is attempting to gain higher-level permissions."},
])
st.table(mapping)

st.markdown("---")
st.subheader("How zero-day fingerprint hypotheses use this mapping")
st.markdown(
    """
    When traffic is flagged **Zero-Day Suspicious**, the system doesn't have a
    confident category — but it still runs the *closest matching* family
    through this same table, and appends **"(hypothesized)"** to make clear
    it's a fingerprint guess, not a certain classification.

    Example: traffic that looks anomalous and is closest to the `Probe`
    centroid is reported as:

    > **MITRE tactic:** Reconnaissance (hypothesized)
    > **Fingerprint guess:** resembles the **Probe** family

    This keeps the analyst informed without overstating the model's
    confidence — a genuinely important distinction in a security tool.
    """
)
