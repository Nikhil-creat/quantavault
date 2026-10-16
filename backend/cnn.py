"""Byte-image CNN: file bytes -> 64x64 image -> {text, binary, encrypted/packed}."""
import math, numpy as np
try:
    import torch, torch.nn as nn
    class ByteCNN(nn.Module):
        def __init__(s):
            super().__init__()
            s.f = nn.Sequential(nn.Conv2d(1,8,3,padding=1), nn.ReLU(), nn.MaxPool2d(2),
                                nn.Conv2d(8,16,3,padding=1), nn.ReLU(), nn.MaxPool2d(2), nn.AdaptiveAvgPool2d(4))
            s.c = nn.Linear(256, 3)
        def forward(s, x): return s.c(s.f(x).flatten(1))
    MODEL = ByteCNN().eval()  # train with train_cnn.py on labelled samples and load weights here
except Exception:
    MODEL = None
LABELS = ["text", "binary", "encrypted_or_packed"]
def entropy(b: bytes) -> float:
    if not b: return 0.0
    c = np.bincount(np.frombuffer(b, np.uint8), minlength=256) / len(b)
    return float(-sum(p*math.log2(p) for p in c if p))
def scan(b: bytes) -> dict:
    h = entropy(b[:65536]); label = LABELS[2] if h > 7.6 else LABELS[1] if h > 6 else LABELS[0]
    out = {"entropy": round(h, 3), "heuristic_label": label, "cnn_probs": None}
    if MODEL is not None and b:
        a = np.resize(np.frombuffer(b[:4096], np.uint8), 4096).reshape(1,1,64,64).astype("float32")/255
        with torch.no_grad(): out["cnn_probs"] = dict(zip(LABELS, torch.softmax(MODEL(torch.from_numpy(a)),1)[0].tolist()))
    return out
