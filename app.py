import streamlit as st
from evaluator import PasswordEvaluator

st.set_page_config(page_title="Hybrid Password Evaluator", layout="centered")

@st.cache_resource
def load_evaluator():
    return PasswordEvaluator()

evaluator = load_evaluator()

st.title("Unified Password Security Evaluation Engine")
st.caption("Hybrid Framework: Information Theory + Dual-Head Transformer + k-Anonymity Breach Validation")

password = st.text_input("Enter Password to Evaluate", type="password")

if password:
    res = evaluator.evaluate(password)
    
    st.subheader(f"Security Score: {res['score']} / 100")
    st.progress(res['score'] / 100.0)
    
    if res['flagged']:
        st.error(f"⚠️ FLAGGED: This credential appeared in {res['breach_count']:,} public data breaches!")
    else:
        st.success("✅ CLEAN: No occurrences found in public breaches.")

    col1, col2, col3 = st.columns(3)
    col1.metric("Shannon Entropy", f"{res['raw_entropy']} bits")
    col2.metric("Transformer P_ML", f"{res['p_ml']:.3f}")
    col3.metric("Breach Penalty (e^-λk)", f"{res['penalty_multiplier']:.4f}")

    with st.expander("Detailed Diagnostic Metrics"):
        st.write(f"- P_good (Randomness confidence): {res['p_good']}")
        st.write(f"- P_bad (Human pattern confidence): {res['p_bad']}")
        st.write(f"- Normalized Entropy: {res['norm_entropy']*100:.1f}%")
