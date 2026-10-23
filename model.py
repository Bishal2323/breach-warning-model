import torch
import torch.nn as nn


class DualHeadTransformer(nn.Module):
    """Must match the architecture in password_model_training.ipynb exactly,
    otherwise dual_head_transformer.pt will not load with strict=True."""

    def __init__(self, vocab_size=96, embed_dim=64, num_heads=4, hidden_dim=128,
                 max_len=32, num_layers=2, dropout=0.1):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_embedding = nn.Embedding(max_len, embed_dim)
        layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads, dim_feedforward=hidden_dim,
            dropout=dropout, batch_first=True
        )
        self.transformer = nn.TransformerEncoder(layer, num_layers=num_layers, enable_nested_tensor=False)
        self.good_head = nn.Sequential(nn.Linear(embed_dim, 32), nn.ReLU(), nn.Linear(32, 1))
        self.bad_head = nn.Sequential(nn.Linear(embed_dim, 32), nn.ReLU(), nn.Linear(32, 1))

    def forward(self, x, return_logits=False):
        pad_mask = (x == 0)
        pos = torch.arange(x.size(1), device=x.device).unsqueeze(0)
        h = self.embedding(x) + self.pos_embedding(pos)
        h = self.transformer(h, src_key_padding_mask=pad_mask)
        keep = (~pad_mask).unsqueeze(-1).to(h.dtype)
        pooled = (h * keep).sum(dim=1) / keep.sum(dim=1).clamp(min=1.0)
        g = self.good_head(pooled).squeeze(1)
        b = self.bad_head(pooled).squeeze(1)
        if return_logits:
            return g, b
        return torch.sigmoid(g), torch.sigmoid(b)
