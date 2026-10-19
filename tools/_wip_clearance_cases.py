import pickle
from safeloadai.static.pickle_static import parse_pickle
def asm(*ops):
    out=b"\x80\x04"
    for o in ops:
        if isinstance(o,str): b=o.encode(); out+=b"\x8c"+bytes([len(b)])+b
        else: out+=o
    return out+b"."
G=lambda m,n:(m,n,b"\x93")
def show(label, *ops):
    flat=[]
    for o in ops: flat+= list(o) if isinstance(o,tuple) else [o]
    r=parse_pickle(asm(*flat))
    print(f"{label:40s}", r["static_risk"], r["reasons"][:2], [(c["item"],c["mechanism"]) for c in r["cleared"]])
M,N="sklearn.metrics._ranking","average_precision_score"
show("referenced in dict", b"}", "f", G(M,N), b"s")
show("called", G(M,N), b")R")
show("memo then called", b"}", "f", G(M,N), b"\x94s", "g", b"h\x00)R", b"s")
show("passed to partial", b"\x8c\tfunctools\x8c\x07partial\x93", G(M,N), b"\x85R")
show("as BUILD target", G(M,N), b"}b")
show("dict key", b"}", G(M,N), "v", b"s")
show("state-only class", "sklearn.linear_model._logistic", "LogisticRegression", b"\x93)\x81}", "C", b"K\x01sb")
show("state-only class called", "sklearn.linear_model._logistic", "LogisticRegression", b"\x93)R")
C=("sklearn.ensemble._voting","VotingRegressor")
show("policy class rebuilt", *C, b"\x93)\x81}", "n", b"K\x01sb")
show("policy class REDUCE", *C, b"\x93)R")
show("policy class slotstate", *C, b"\x93)\x81N}", "n", b"K\x01s\x86b")
show("policy class as value", b"}", "c", *C, b"\x93s")
show("policy instance called", *C, b"\x93)\x81}b)R")
