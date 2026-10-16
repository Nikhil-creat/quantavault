"""Train ByteCNN. Usage: python train_cnn.py data/  (subfolders: text/ binary/ encrypted_or_packed/)"""
import sys, pathlib, numpy as np, torch, torch.nn as nn
from cnn import ByteCNN, LABELS
root = pathlib.Path(sys.argv[1]); X, Y = [], []
for i, l in enumerate(LABELS):
    for p in (root/l).glob("*"):
        if p.is_file(): X.append(np.resize(np.frombuffer(p.read_bytes()[:4096], np.uint8), 4096).reshape(1,64,64)/255); Y.append(i)
X = torch.tensor(np.array(X), dtype=torch.float32); Y = torch.tensor(Y); m = ByteCNN(); o = torch.optim.Adam(m.parameters(), 1e-3)
for ep in range(30):
    o.zero_grad(); loss = nn.functional.cross_entropy(m(X), Y); loss.backward(); o.step()
    print(ep, round(loss.item(), 4))
torch.save(m.state_dict(), "bytecnn.pt")  # then load in cnn.py: MODEL.load_state_dict(torch.load("bytecnn.pt"))
