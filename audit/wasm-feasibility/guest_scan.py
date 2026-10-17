import pickle, io, json, sys, marshal, base64, dis, types, time
t0 = time.perf_counter()
log = []
class Stub:
    def __init__(self, name): self._n = name
    def __call__(self, *a, **k):
        log.append({"call": self._n, "args": [repr(x)[:80] for x in a]}); return Stub(self._n + "()")
    def __getattr__(self, attr): return Stub(self._n + "." + attr)
class U(pickle.Unpickler):
    def find_class(self, module, name):
        log.append({"import": f"{module}.{name}"}); return Stub(f"{module}.{name}")
try:
    U(open("/in/sample.pkl", "rb")).load(); ok = True
except Exception as e:
    ok = f"{type(e).__name__}: {e}"
res = {"pickle_ok": ok, "unpickler_cls": U.__mro__[1].__module__ + "." + U.__mro__[1].__name__, "log": log}
# Lambda analysis: same-version code object built in-guest
def walk(co, out):
    out["names"] += list(co.co_names); out["consts"] += [c for c in co.co_consts if isinstance(c, (str, int))]
    for c in co.co_consts:
        if isinstance(c, types.CodeType): walk(c, out)
same = base64.b64encode(marshal.dumps(compile('lambda x: __import__("os").system("echo MARKER") or x', '<l>', 'eval')))
out = {"names": [], "consts": []}; walk(marshal.loads(base64.b64decode(same)), out); res["lambda_same_version"] = out
try:
    co = marshal.loads(base64.b64decode(open("/in/lambda313.b64").read()))
    o2 = {"names": [], "consts": []}; walk(co, o2); res["lambda_313_in_312"] = o2
except Exception as e:
    res["lambda_313_in_312"] = f"{type(e).__name__}: {e}"
try:
    import io as _io; b=_io.StringIO(); dis.dis(co, file=b); res["dis_313_in_312_head"] = b.getvalue()[:300]
except Exception as e: res["dis_313_in_312_head"] = f"{type(e).__name__}: {e}"
res["guest_ms"] = round((time.perf_counter() - t0) * 1000, 1)
print(json.dumps(res))
