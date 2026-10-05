# Hybrid Password Security Evaluation Engine

An academic research prototype developed under the Warhawk Scholars Program. This engine replaces heuristic rule-based classifiers (e.g., `zxcvbn`) with a hybrid formulation:

$$S = (\alpha \cdot \text{NormalizedEntropy} + \beta \cdot P_{ML}) \cdot e^{-\lambda k}$$

### Key Components:
1. **Shannon Entropy**: Theoretical search space measurement ($L \cdot \log_2(R)$) normalized against an 80-bit ceiling.
2. **Dual-Head Transformer ($P_{ML}$)**: Character-level attention architecture outputting $P_{\text{good}}$ and $P_{\text{bad}}$.
3. **Empirical Breach Penalty**: Real-time Have I Been Pwned $k$-anonymity verification providing exponential decay ($e^{-\lambda k}$).
4. **Scoring Scale**: Continuous 0–100 score with automatic compromise flagging.
