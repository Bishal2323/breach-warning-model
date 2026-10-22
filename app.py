import streamlit as st
from evaluator import PasswordEvaluator, MAX_LEN

st.set_page_config(
    page_title="Warhawk Hybrid Password Security Evaluator",
    page_icon="🛡️",
    layout="centered"
)

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

try:
    evaluator = load_evaluator()
except FileNotFoundError as e:
    st.error(str(e))
    st.stop()

st.title("🛡️ Warhawk Password Security Engine")
st.caption("Hybrid Framework: Information Theory + Dual-Head Transformer + Live Breach Threat Intelligence")

password = st.text_input("Enter Password to Evaluate", type="password", placeholder="Type a password or passphrase...")

SECONDS_PER_YEAR = 31536000


def estimate_crack_time(adjusted_entropy, breach_count, breach_checked):
    """Illustrative estimate only: average-case brute force over the structure-adjusted
    search space at a fixed guess rate. It is not a model of real attacker behavior."""
    if breach_count > 0:
        return "Instant (< 1 millisecond)", "Appears in breach corpora, so it would be tried in a dictionary attack first."

    if adjusted_entropy > 200:
        return "Centuries / Infeasible", "Beyond classical brute-force capacity."

    # ~100 billion guesses/sec (e.g. multi-GPU rig against a fast hash such as NTLM/MD5)
    guesses_per_sec = 1e11
    seconds = (2 ** adjusted_entropy / 2) / guesses_per_sec

    if seconds < 1:
        return "Less than a second", "Trivial offline GPU brute force."
    elif seconds < 60:
        return f"{int(seconds)} seconds", "Fast hash cracking."
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes", "Short GPU cluster session."
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours", "Standard password dump attack."
    elif seconds < SECONDS_PER_YEAR:
        return f"{int(seconds / 86400)} days", "Moderate resistance."
    elif seconds < SECONDS_PER_YEAR * 100:
        return f"{int(seconds / SECONDS_PER_YEAR)} years", "Resistant against brute force."
    elif seconds < SECONDS_PER_YEAR * 1_000_000:
        return f"{int(seconds / SECONDS_PER_YEAR):,} years", "Very strong against brute force."
    else:
        return "Centuries / Infeasible", "Beyond classical brute-force capacity."

def generate_suggestions(password, res):
    suggestions = []

    if res["flagged"]:
        suggestions.append("🚨 **Immediately discard this password**: It exists in publicly circulated breach corpora, and attackers test these first.")

    if not res["breach_checked"]:
        suggestions.append("🌐 **Re-run the breach check**: The Have I Been Pwned lookup failed, so this password has not been verified against known breaches.")

    if len(password) < 14:
        suggestions.append(f"📏 **Increase length**: Current length is {len(password)}. Aim for at least 14–16 characters to push the search space beyond GPU cluster capacity.")

    if res["adjusted_entropy"] < res["raw_entropy"] * 0.85:
        suggestions.append("🔁 **Avoid repeats and sequences**: Repeated characters and runs like 'abc' or '123' were discounted from your effective length.")

    if res["p_bad"] > 0.4:
        suggestions.append("🧩 **Eliminate human pattern predictability**: The Transformer detected repetitive syllables or leetspeak substitutions (e.g., '@' for 'a', digits at the end). Consider a 4-word random passphrase with punctuation.")

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

    if not suggestions and res["breach_checked"]:
        suggestions.append("🌟 **Excellent entropy and structure**: High randomness and no known compromise history.")

    return suggestions


if password:
    res = evaluator.evaluate(password)
    score = res["score"]

    if score >= 85:
        tier_label, color = "EXCELLENT / CRYPTOGRAPHIC", "#238636"
    elif score >= 65:
        tier_label, color = "STRONG / ROBUST", "#2ea043"
    elif score >= 40:
        tier_label, color = "MODERATE / VULNERABLE", "#d29922"
    else:
        tier_label, color = "CRITICAL / COMPROMISED", "#da3633"

    st.markdown(
        f"""
        <div class="score-badge" style="background-color: {color}22; border: 2px solid {color}; color: {color};">
            Security Score: {score} / 100
            <div style="font-size: 1rem; font-weight: 500; margin-top: 4px;">Tier: {tier_label}</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.progress(min(1.0, score / 100.0))

    # Breach banner: three distinct states
    if res["flagged"]:
        st.error(f"⚠️ **FLAGGED: COMPROMISED CREDENTIAL**: Found in **{res['breach_count']:,}** public data breaches! (Score penalized via exponential decay).")
    elif not res["breach_checked"]:
        st.warning("❓ **BREACH CHECK UNAVAILABLE**: Could not reach the breach database. This score does not include a breach penalty and the password is **not** verified as clean.")
    else:
        st.success("✅ **CLEAN**: Zero occurrences identified in global breach intelligence.")

    if res["truncated"]:
        st.warning(f"✂️ Password is longer than {MAX_LEN} characters. Entropy uses the full password, but the Transformer only analyzed the first {MAX_LEN}.")
    if res["non_ascii"]:
        st.warning("🔤 Non-ASCII characters detected. The Transformer was trained on printable ASCII only, so its pattern score is less reliable for this input.")

    crack_time, crack_desc = estimate_crack_time(res["adjusted_entropy"], res["breach_count"], res["breach_checked"])
    st.markdown(
        f"""
        <div class="crack-box">
            <b>Illustrative Time to Crack (Offline GPU Brute Force):</b> <span style="font-size: 1.15rem; color: #58a6ff;">{crack_time}</span><br>
            <span style="font-size: 0.85rem; color: #8b949e;">{crack_desc}</span><br>
            <span style="font-size: 0.75rem; color: #8b949e;">Assumes 10¹¹ guesses/sec against the structure-adjusted search space. Real attackers use dictionaries and rules, so treat this as a rough upper bound.</span>
        </div>
        """,
        unsafe_allow_html=True
    )
    col1, col2, col3 = st.columns(3)
    col1.metric("Adjusted Entropy", f"{res['adjusted_entropy']} bits", help=f"Raw L·log2(R) = {res['raw_entropy']} bits, discounted for repeats and sequences")
    col2.metric("Transformer P_ML", f"{res['p_ml']:.3f}", help="Neural structural analysis combining randomness vs human patterns")
    col3.metric("Breach Decay Factor", f"{res['penalty_multiplier']:.4f}", help="e^(-0.05 * k) penalty multiplier")

    st.subheader("💡 Recommendations & Analysis")
    for sug in generate_suggestions(password, res):
        st.markdown(f"- {sug}")

    with st.expander("🔬 View Deep Model Diagnostics (Academic Metrics)"):
        st.write(f"- **P_good (Randomness Confidence):** `{res['p_good']:.4f}`")
        st.write(f"- **P_bad (Human Predictability Confidence):** `{res['p_bad']:.4f}`")
        st.write(f"- **Raw Entropy:** `{res['raw_entropy']}` bits")
        st.write(f"- **Adjusted Entropy:** `{res['adjusted_entropy']}` bits")
        st.write(f"- **Normalized Entropy ($0\\to1$ scale):** `{res['norm_entropy']*100:.2f}%`")
        breach_text = f"{res['breach_count']:,}" if res["breach_checked"] else "unverified"
        st.write(f"- **Raw Breach Count ($k$):** `{breach_text}`")
        st.latex(r"S = (\alpha \cdot \text{NormEntropy} + \beta \cdot P_{ML}) \cdot e^{-\lambda k}")
