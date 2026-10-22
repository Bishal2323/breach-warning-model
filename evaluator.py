import math
import os
import string
import hashlib
import requests
import torch
from model import DualHeadTransformer

CHAR_POOL = string.ascii_letters + string.digits + string.punctuation
CHAR_TO_IDX = {char: idx + 1 for idx, char in enumerate(CHAR_POOL)}
MAX_LEN = 32
NON_ASCII_POOL = 100  # rough allowance for characters outside printable ASCII


def _pool_size(pwd):
    pool = 0
    if any(c.islower() and c.isascii() for c in pwd): pool += 26
    if any(c.isupper() and c.isascii() for c in pwd): pool += 26
    if any(c.isdigit() and c.isascii() for c in pwd): pool += 10
    if any(c in string.punctuation for c in pwd): pool += len(string.punctuation)
    if any(not c.isascii() for c in pwd): pool += NON_ASCII_POOL
    return pool


def calculate_entropy(pwd):
    """Naive Shannon-style search space: L * log2(R). Assumes uniformly random characters."""
    pool = _pool_size(pwd)
    if pool == 0 or len(pwd) == 0:
        return 0.0
    return len(pwd) * math.log2(pool)


def effective_length(pwd):
    """Length discounted for structure humans lean on: repeated characters
    (case-insensitive) and ascending/descending runs like 'abc' or '321'.
    Each such character counts as half a character."""
    seen = set()
    total = 0.0
    for i, c in enumerate(pwd):
        w = 1.0
        if c.lower() in seen:
            w = 0.5
        if i >= 2:
            d1 = ord(pwd[i]) - ord(pwd[i - 1])
            d2 = ord(pwd[i - 1]) - ord(pwd[i - 2])
            if abs(d1) == 1 and d1 == d2:
                w = min(w, 0.5)
        seen.add(c.lower())
        total += w
    return total


def calculate_adjusted_entropy(pwd):
    """Entropy using the structure-discounted length instead of raw length."""
    pool = _pool_size(pwd)
    if pool == 0 or len(pwd) == 0:
        return 0.0
    return effective_length(pwd) * math.log2(pool)


def get_breach_count(password):
    """Returns the breach count (0 if not found), or None if the check could not be completed."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url, timeout=4, headers={"Add-Padding": "true"})
        if res.status_code != 200:
            return None
        for line in res.text.splitlines():
            h, count = line.strip().split(":")
            if h == suffix:
                return int(count)
        return 0
    except Exception:
        return None


class PasswordEvaluator:
    def __init__(self, weights_path="dual_head_transformer.pt", device=None):
        if not os.path.exists(weights_path):
            raise FileNotFoundError(
                f"Model weights not found at '{weights_path}'. "
                "Train the model or place the checkpoint next to evaluator.py."
            )
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = DualHeadTransformer(vocab_size=len(CHAR_POOL) + 1).to(self.device)
        self.model.load_state_dict(torch.load(weights_path, map_location=self.device))
        self.model.eval()

    def evaluate(self, password, alpha=0.4, beta=0.6, lam=0.05):
        raw_entropy = calculate_entropy(password)
        adj_entropy = calculate_adjusted_entropy(password)
        norm_entropy = min(1.0, adj_entropy / 80.0)

        truncated = len(password) > MAX_LEN
        non_ascii = any(not c.isascii() for c in password)

        indices = [CHAR_TO_IDX.get(c, 0) for c in password[:MAX_LEN]]
        indices += [0] * (MAX_LEN - len(indices))
        x = torch.tensor([indices], dtype=torch.long).to(self.device)

        with torch.no_grad():
            p_good, p_bad = self.model(x)
            p_good = p_good.item()
            p_bad = p_bad.item()

        p_ml = (p_good + (1.0 - p_bad)) / 2.0

        k = get_breach_count(password)
        breach_checked = k is not None
        k_eff = k if breach_checked else 0
        breach_penalty = math.exp(-lam * k_eff)
        final_score = (alpha * norm_entropy + beta * p_ml) * breach_penalty * 100.0

        return {
            "password": password,
            "raw_entropy": round(raw_entropy, 2),
            "adjusted_entropy": round(adj_entropy, 2),
            "norm_entropy": round(norm_entropy, 4),
            "p_good": round(p_good, 4),
            "p_bad": round(p_bad, 4),
            "p_ml": round(p_ml, 4),
            "breach_count": k_eff,
            "breach_checked": breach_checked,
            "penalty_multiplier": round(breach_penalty, 6),
            "score": round(final_score, 1),
            "flagged": k_eff > 0,
            "truncated": truncated,
            "non_ascii": non_ascii,
        }
