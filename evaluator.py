import math
import string
import hashlib
import requests
import torch
from model import DualHeadTransformer

CHAR_POOL = string.ascii_letters + string.digits + string.punctuation
CHAR_TO_IDX = {char: idx + 1 for idx, char in enumerate(CHAR_POOL)}
MAX_LEN = 32

def calculate_entropy(pwd):
    pool = 0
    if any(c.islower() for c in pwd): pool += 26
    if any(c.isupper() for c in pwd): pool += 26
    if any(c.isdigit() for c in pwd): pool += 10
    if any(c in string.punctuation for c in pwd): pool += len(string.punctuation)
    if pool == 0 or len(pwd) == 0: return 0.0
    return len(pwd) * math.log2(pool)

def get_breach_count(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url, timeout=4)
        if res.status_code == 200:
            for line in res.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return int(count)
    except Exception:
        pass
    return 0

class PasswordEvaluator:
    def __init__(self, weights_path="dual_head_transformer.pt", device=None):
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = DualHeadTransformer(vocab_size=len(CHAR_POOL) + 1).to(self.device)
        self.model.load_state_dict(torch.load(weights_path, map_location=self.device))
        self.model.eval()

    def evaluate(self, password, alpha=0.4, beta=0.6, lam=0.05):
        raw_entropy = calculate_entropy(password)
        norm_entropy = min(1.0, raw_entropy / 80.0)

        indices = [CHAR_TO_IDX.get(c, 0) for c in password[:MAX_LEN]]
        indices += [0] * (MAX_LEN - len(indices))
        x = torch.tensor([indices], dtype=torch.long).to(self.device)

        with torch.no_grad():
            p_good, p_bad = self.model(x)
            p_good = p_good.item()
            p_bad = p_bad.item()

        p_ml = (p_good + (1.0 - p_bad)) / 2.0
        k = get_breach_count(password)
        breach_penalty = math.exp(-lam * k)
        final_score = (alpha * norm_entropy + beta * p_ml) * breach_penalty * 100.0

        return {
            "password": password,
            "raw_entropy": round(raw_entropy, 2),
            "norm_entropy": round(norm_entropy, 4),
            "p_good": round(p_good, 4),
            "p_bad": round(p_bad, 4),
            "p_ml": round(p_ml, 4),
            "breach_count": k,
            "penalty_multiplier": round(breach_penalty, 6),
            "score": round(final_score, 1),
            "flagged": k > 0
        }
