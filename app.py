import streamlit as st
import math
import time
from evaluator import PasswordEvaluator

st.set_page_config(
    page_title="Warhawk Hybrid Password Security Evaluator",
    page_icon="🛡️",
    layout="centered"
)

# Custom Styling for polished presentation
st.markdown("""
<style>
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 10px;
    }
    .score-badge {
        font-size: 2.2rem;
        font-weight: 700;
        text-align: center;
        padding: 10px;
        border-radius: 10px;
        margin: 15px 0;
    }
    .crack-box {
        background-color: #0d1117;
        border-left: 5px solid #58a6ff;
        padding: 12px 18px;
        border-radius: 6px;
        margin: 15px 0;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_evaluator():
    return PasswordEvaluator()

evaluator = load_evaluator()

st.title("🛡️ Warhawk Password Security Engine")
st.caption("Hybrid Framework: Information Theory + Dual-Head Transformer + Live Breach Threat Intelligence")

password = st.text_input("Enter Password to Evaluate", type="password", placeholder="Type a password or passphrase...")

def estimate_crack_time(raw_entropy, p_ml, breach_count):
    if breach_count > 0:
        return "Instant (< 1 millisecond)", "Compromised via credential stuffing dictionary attack."
    
    # Effective search space adjusted by Transformer pattern probability
    # Lower P_ML means predictable structure (reduced search space)
    effective_entropy = raw_entropy * max(0.2, p_ml)
    guesses = 2 ** effective_entropy
    
    # Modern offline cracking cluster (e.g. 8x RTX 4090 ~ 100 billion guesses/sec for NTLM/MD5)
    guesses_per_sec = 1e11
    seconds = guesses / guesses_per_sec
    
    if seconds < 1:
        return "Less than a second", "Trivial offline GPU brute force."
    elif seconds < 60:
        return f"{int(seconds)} seconds", "Fast hash collision."
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes", "Short GPU cluster session."
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours", "Standard password dump attack."
    elif seconds < 31536000:
        return f"{int(seconds / 86400)} days", "Moderate resistance."
    elif seconds < 31536000 * 100:
        return f"{int(seconds / 31536000)} years", "Resistant against brute force."
    elif seconds < 31536000 * 1000000:
        return f"{int(seconds / 31536000):,} years", "Cryptographically robust."
    else:
        return "Centuries / Infeasible", "Beyond classical computing brute-force capacity."

def generate_suggestions(password, res):
    suggestions = []
    
    if res['flagged']:
        suggestions.append("🚨 **Immediately discard this password**: It exists in publicly circulated breach corpora. Attackers test these in millisecond 1.")
    
    if len(password) < 14:
        suggestions.append(f"📏 **Increase length**: Current length is {len(password)}. Aim for at least 14–16 characters to push search space beyond GPU cluster capacity.")
        
    if res['p_bad'] > 0.4:
        suggestions.append("🧩 **Eliminate human pattern predictability**: The Transformer detected repetitive syllable or leetspeak substitutions (e.g., '@' for 'a', digits at end). Consider a 4-word random passphrase with punctuation.")
        
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_sym = any(not c.isalnum() for c in password)
    
    missing_classes = []
    if not has_upper: missing_classes.append("uppercase letters")
    if not has_lower: missing_classes.append("lowercase letters")
    if not has_digit: missing_classes.append("numbers")
    if not has_sym: missing_classes.append("special symbols")
    
    if missing_classes:
        suggestions.append(f"🔠 **Expand character set**: Add {', '.join(missing_classes)} to expand base entropy.")
        
    if not suggestions:
        suggestions.append("🌟 **Excellent entropy and structure**: This credential exhibits high cryptographic randomness and zero known compromise history.")
        
    return suggestions

if password:
    res = evaluator.evaluate(password)
    score = res['score']
    
    # Dynamic 0-100 Score Color Grading
    if score >= 85:
        tier_label = "EXCELLENT / CRYPTOGRAPHIC"
        color = "#238636" # Green
    elif score >= 65:
        tier_label = "STRONG / ROBUST"
        color = "#2ea043" # Light Green
    elif score >= 40:
        tier_label = "MODERATE / VULNERABLE"
        color = "#d29922" # Orange
    else:
        tier_label = "CRITICAL / COMPROMISED"
        color = "#da3633" # Red
        
    st.markdown(
        f"""
        <div class="score-badge" style="background-color: {color}22; border: 2px solid {color}; color: {color};">
            Security Score: {score} / 100
            <div style="font-size: 1rem; font-weight: 500; margin-top: 4px;">Tier: {tier_label}</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    st.progress(score / 100.0)
    
    # Breach Alert Banner
    if res['flagged']:
        st.error(f"⚠️ **FLAGGED: COMPROMISED CREDENTIAL** — Found in **{res['breach_count']:,}** public data breaches! (Score penalized via exponential decay).")
    else:
        st.success("✅ **CLEAN**: Zero occurrences identified in global breach intelligence.")
        
    # Time to Crack Box
    crack_time, crack_desc = estimate_crack_time(res['raw_entropy'], res['p_ml'], res['breach_count'])
    st.markdown(
        f"""
        <div class="crack-box">
            <b>Estimated Time to Crack (Offline GPU Attack):</b> <span style="font-size: 1.15rem; color: #58a6ff;">{crack_time}</span><br>
            <span style="font-size: 0.85rem; color: #8b949e;">{crack_desc}</span>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    # 3-Column Core Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Shannon Entropy", f"{res['raw_entropy']} bits", help="Measures brute-force search space: L * log2(R)")
    col2.metric("Transformer P_ML", f"{res['p_ml']:.3f}", help="Neural structural analysis combining randomness vs human patterns")
    col3.metric("Breach Decay Factor", f"{res['penalty_multiplier']:.4f}", help="e^(-0.05 * k) penalty multiplier")

    # Actionable Suggestion Box
    st.subheader("💡 Recommendations & Analysis")
    suggestions = generate_suggestions(password, res)
    for sug in suggestions:
        st.markdown(f"- {sug}")

    # Expandable Technical Diagnostics
    with st.expander("🔬 View Deep Model Diagnostics (Academic Metrics)"):
        st.write(f"- **P_good (Randomness Confidence):** `{res['p_good']:.4f}`")
        st.write(f"- **P_bad (Human Predictability Confidence):** `{res['p_bad']:.4f}`")
        st.write(f"- **Normalized Entropy ($0\\to1$ scale):** `{res['norm_entropy']*100:.2f}%`")
        st.write(f"- **Raw Breach Count ($k$):** `{res['breach_count']:,}`")
        st.latex(r"S = (\alpha \cdot \text{NormEntropy} + \beta \cdot P_{ML}) \cdot e^{-\lambda k}")