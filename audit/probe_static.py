"""Static-only probes against PR #4 parsers. Nothing here deserializes."""
import io, json, sys, zipfile
sys.path.insert(0, sys.argv[1])
from sandbox_rce import parser, parser_keras, pipeline, sandbox

def P(data): r = parser.parse_pickle(data); return r["static_risk"], [(i["module"], i["symbol"]) for i in r["imports"]]

# 1. import-time side effect, no call opcode (GLOBAL only)
print("antigravity GLOBAL only:", P(b"cantigravity\nfly\n."))
# 2. NEWOBJ instead of REDUCE on unknown class
print("unknown class + NEWOBJ:", P(b"\x80\x02cfoo.bar\nBaz\n)\x81."))
# 3. allowlisted-by-capital-letter scipy class called via REDUCE (file truncation gadget)
print("scipy.io FortranFile REDUCE:", P(b"\x80\x02cscipy.io\nFortranFile\nX\x0f\x00\x00\x00/tmp/victim.txtX\x01\x00\x00\x00w\x86R."))
# 4. torch-style zip routed to pickle parser
b = io.BytesIO()
with zipfile.ZipFile(b, "w") as z: z.writestr("archive/data.pkl", b"\x80\x02}q\x00.")
print("torch zip as pickle:", parser.parse_pickle(b.getvalue())["static_risk"])

def K(cfg):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z: z.writestr("config.json", json.dumps(cfg))
    return parser_keras.parse_keras(b.getvalue())
# 5. module prefix not boundary-aware
for mod in ["tf_evil_pkg", "kerasx", "tensorflow_backdoor", "keras.utils"]:
    r = K({"class_name": "Functional", "config": {"layers": [{"class_name": "get_file", "module": mod, "config": {}, "registered_name": "get_file"}]}})
    print(f"keras module={mod!r}:", r["static_risk"])
# 6. deeply nested config
deep = {"class_name": "Dense"}
for _ in range(400): deep = {"a": [deep]}
try: print("deep config:", K(deep)["static_risk"])
except RecursionError as e: print("deep config: RecursionError escapes parse_keras")
# 7. zip bomb: config.json decompressed size not checked before read
b = io.BytesIO()
with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z: z.writestr("config.json", b" " * (200 * 1024 * 1024))
print("bomb archive bytes:", len(b.getvalue()), "-> parse_keras reads 200 MB member with no size check")
import tracemalloc; tracemalloc.start(); parser_keras.parse_keras(b.getvalue()); print("  peak MB:", tracemalloc.get_traced_memory()[1] // 2**20)
# 8. judge downgrades static 'suspicious'
print("judge vs static suspicious:", pipeline.final_verdict({"static_risk": "suspicious"}, {"available": True, "verdict": "safe"}, {"events": [], "detonated": True, "load_succeeded": True}))
# 9. forged in-band result line from payload in same process
out = '@@EVENT@@ {"type":"os_system","detail":"touch x"}\n@@RESULT@@ {"load_succeeded": true, "events": []}\n'
ev, res = sandbox._parse_detoner_output(out)
print("forged RESULT -> events reported:", res["events"], "(real event dropped:", ev, ")")
