import torch
import torch.nn as nn

class DualHeadTransformer(nn.Module):
    def __init__(self, vocab_size=96, embed_dim=64, num_heads=4, hidden_dim=128):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads, dim_feedforward=hidden_dim, batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=2)
        self.good_head = nn.Sequential(nn.Linear(embed_dim, 32), nn.ReLU(), nn.Linear(32, 1), nn.Sigmoid())
        self.bad_head = nn.Sequential(nn.Linear(embed_dim, 32), nn.ReLU(), nn.Linear(32, 1), nn.Sigmoid())

    def forward(self, x):
        embedded = self.embedding(x)
        encoded = self.transformer(embedded)
        pooled = torch.mean(encoded, dim=1)
        return self.good_head(pooled).squeeze(1), self.bad_head(pooled).squeeze(1)
