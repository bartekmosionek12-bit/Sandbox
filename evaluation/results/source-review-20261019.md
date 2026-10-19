# Source review: torch.nn / torchvision / ultralytics / xgboost pickle globals (tune half only)

Repo: /home/user/Sandbox, branch fix/polyglot-builtins-corpus (HEAD 638277d). No file in the repo was edited.
Data: `evaluation/results/eval-hub-1k-20261019T143515Z.json`, entries with `group == "hf-tune"` only (435 files from 347 repos).
Counts come from each entry's `results.safeloadai.missing`, deduplicated per file. That run reports safeloadai 0.5.0, which predates
commit 0f733b1 (the per-use getattr rule). So its `__builtin__.getattr` = MALICIOUS lines come from the old rule (see section 4).

## 1. Downloads (PyPI only, `pip download --no-deps --only-binary=:all:`, unzipped and read, never installed, imported or run)

Downloaded to a scratch directory outside the repo (not committed).

| file | sha256 |
|---|---|
| torch/torch-2.11.0-cp312-cp312-macosx_11_0_arm64.whl | 4b5866312ee6e52ea625cd211dcb97d6a2cdc1131a5f15cc0d87eec948f6dd34 |
| torchvision/torchvision-0.26.0-cp312-cp312-macosx_11_0_arm64.whl | c409e1c3fdebec7a3834465086dbda8bf7680eff79abf7fd2f10c6b59520a7a4 |
| ultralytics/ultralytics-8.4.182-py3-none-any.whl (latest) | 11b90b26fa30f878807b0b8c4ed1870eb3c54e7e876a17a936bd92065a7e743b |
| ultralytics-8.3/ultralytics-8.3.40-py3-none-any.whl | 68eab78f4bdcd7ab2f62f5fe5a394958dd8507c47359a7f7930ab617ffba4302 |
| ultralytics-8.3.0/ultralytics-8.3.0-py3-none-any.whl | 3137c4921c18c8ddf610f64f1badc2dad2a9fd182e10218c2bbb29caee308b9e |
| ultralytics-8.2.103/ultralytics-8.2.103-py3-none-any.whl | 34705d2798c662509beeeb7177699b4696a7b34d60a8834d580f9a85593b358e |
| ultralytics-8.0/ultralytics-8.0.50-py3-none-any.whl (old single-file `nn/modules.py`, `yolo/utils`) | 60c409292cab97ba9893cf7a60a0b2a385f82c7a7f007206a53c0075737dda57 |
| xgboost/xgboost-3.4.1-py3-none-macosx_12_0_arm64.whl (latest) | a7afd7dbace0951c93aa85ffe046e54bc40893f5b51cd3e7991eb157bf9c7c7c |
| xgboost-1.5/xgboost-1.5.2-py3-none-macosx_10_15_x86_64.macosx_11_0_x86_64.macosx_12_0_x86_64.whl (has `compat.XGBoostLabelEncoder`) | 51b5dfe553d78ab92f2c60ccead6abc38196c2961f6952f6ec14b1feba6ffd25 |

- torch 2.14.1 is listed on PyPI but has no macOS arm64 wheel, so I used 2.11.0, the newest version with one, which matches torchvision 0.26.0.
- File paths below are relative to each wheel's root, e.g. `torch/nn/modules/module.py`. Ultralytics paths are for 8.4.182 unless marked (8.0.50).

## 2. How torch.save pickles an nn.Module

- `torch/serialization.py:59` sets `DEFAULT_PROTOCOL = 2`. `torch.save` uses the stdlib `pickle_module.Pickler` with only `persistent_id` added for storages (`serialization.py:1249`). There is no `reducer_override`.
- `nn.Module` (`module.py:408`) defines no `__reduce__`, `__reduce_ex__` or `__getnewargs__`. So `object.__reduce_ex__(2)` applies: `copyreg.__newobj__` → **`GLOBAL cls`, `EMPTY_TUPLE`, `NEWOBJ`**, then the state dict, then **`BUILD`**. `copyreg._reconstructor` is used only for protocol 0/1.
- I confirmed the form with stand-in classes of my own (no torch or ultralytics code) through stdlib `pickle` and `pickletools`: a class with a Module-like `__getstate__`/`__setstate__` gives `GLOBAL; EMPTY_TUPLE; NEWOBJ; {...}; BUILD`. That is exactly the form `_argument_check` accepts for STATE_ONLY_CLASSES (`how == "newobj" and args == ()`).
- `Module.__getstate__` (`module.py:1920`) returns `__dict__.copy()` minus `_compiled_call_impl`.
- `Module.__setstate__` (`module.py:1925`) runs `self.__dict__.update(state)`, then for each missing hook dict assigns a fresh empty `OrderedDict()`/`set()`/`None` (lines 1929-1950).
  - Those assignments go through `Module.__setattr__` (`module.py:1972`). With an OrderedDict, set or None as the value, the only possible outcomes are `object.__setattr__` or a TypeError/AttributeError. A TypeError happens when the state put that name into `_parameters`, `_modules` or `_buffers`.
  - The global module-registration hooks (`module.py:2014`, `2025`) run only for Module values, and they are process globals, not file contents.
  - Hook dicts restored from the state (`_forward_hooks` and the rest) are only stored. Nothing calls them while loading, and any callable inside them is its own GLOBAL, which the scanner checks.
  - `_load_from_state_dict` and the load_state_dict pre/post hooks are not called by unpickling.
- `Module.__getattr__` (`module.py:1955`) only looks up `_parameters`, `_buffers` and `_modules`, otherwise it raises.
- No `__init_subclass__`, metaclass or `__new__` in `torch/nn/modules/*.py`.
- The only subclass hooks in `torch/nn/modules`:
  - `_ConvNd.__setstate__` (`conv.py:209`): sets a `padding_mode` default.
  - `Upsample.__setstate__` (`upsampling.py:183`): sets a `recompute_scale_factor` default.
  - AvgPool3d (`pooling.py:906`), MultiheadAttention and other activations (`activation.py:1248` ff.), Transformer layers (`transformer.py:794`, `1084`): set defaults.
  - `RNNBase.__setstate__`/`__setattr__` (`rnn.py:419`, `rnn.py:230`): rebuilds the weight lists and runs custom `__setattr__` logic. Not on tune, so leave it out.
  - Lazy modules (`LazyModuleMixin`): register hooks in `__init__` and are not on tune, so leave them out.
- Plain non-Module classes (torchvision `Compose`/`ToTensor`, ultralytics `v8DetectionLoss`/`E2ELoss`) also pickle as `NEWOBJ ()` + `BUILD`. They have no `__setstate__`, so BUILD just updates `__dict__`.
  - Caveat for the scanner owner: a BUILD state given as a `(dict, slotstate)` tuple makes pickle call `setattr()` for each slot item, which would run property setters or a custom `__setattr__`. None of the classes recommended below that lack `__setstate__` defines either.

## 3. Pair table (tune files = hf-tune files whose `missing` lists the pair)

| pair | tune files | decision | reason (file:line in the downloaded source) |
|---|---|---|---|
| torch.nn.modules.activation.SiLU | 27 | add state-only | `activation.py:435`. Module hooks only (`module.py:1925`), no own pickling hooks. |
| torch.nn.modules.container.ModuleList | 27 | add state-only | `container.py:335`. No own `__setstate__`/`__getattr__`/`__setattr__`. |
| torch.nn.modules.container.Sequential | 27 | add state-only | `container.py:59`. Same as ModuleList. |
| torch.nn.modules.batchnorm.BatchNorm2d | 27 | add state-only | `batchnorm.py:393`. `_NormBase._load_from_state_dict` does not run on unpickle. Not the Lazy variant. |
| torch.nn.modules.conv.Conv2d | 27 | add state-only | `conv.py:378`. `_ConvNd.__setstate__` (`conv.py:209`) only sets the `padding_mode` default. |
| torch.nn.modules.pooling.MaxPool2d | 24 | add state-only | `pooling.py:155`. No own hooks. |
| torch.nn.modules.upsampling.Upsample | 24 | add state-only | `upsampling.py:13`. `__setstate__` (`:183`) only sets a default key. |
| torch.nn.modules.linear.Identity | 11 | add state-only | `linear.py:22`. No hooks. |
| torch.nn.modules.linear.Linear | 4 | add state-only | `linear.py:53`. No hooks. LazyLinear (`:259`) is a different class and stays out. |
| torch.nn.modules.conv.ConvTranspose2d | 3 | add state-only | `conv.py:1000`. Inherits `_ConvNd.__setstate__` (default only). |
| torch.nn.modules.dropout.Dropout | 3 | add state-only | `dropout.py:35`. No hooks. |
| torch.nn.modules.pooling.AdaptiveAvgPool2d | 3 | add state-only | `pooling.py:1473`. No hooks. |
| torch.nn.modules.loss.BCEWithLogitsLoss | 2 | add state-only | `loss.py:715`. `_Loss` (`:38`) has no hooks; `pos_weight`/`weight` are buffers. |
| torchvision.transforms.transforms.Compose | 3 | add state-only | `transforms/transforms.py:60`. Plain class holding a list; nothing is called on load. |
| torchvision.transforms.transforms.ToTensor | 3 | add state-only | `transforms.py:107`. Plain class, no hooks. |
| torchvision.transforms.transforms.Normalize | 3 | add state-only | `transforms.py:252`. nn.Module, no own hooks. |
| torchvision.transforms.transforms.Resize | 3 | add state-only | `transforms.py:291`. nn.Module, no own hooks. |
| torchvision.transforms.transforms.CenterCrop | 3 | add state-only | `transforms.py:369`. nn.Module, no own hooks. |
| torchvision.transforms.functional.InterpolationMode | 3 | leave out of STATE_ONLY; ENUM_CLASSES candidate | `functional.py:23`, `class InterpolationMode(Enum)` with str values. Enum pickles as `REDUCE cls('bilinear')`, which fits the ENUM_CLASSES check, not state-only. |
| ultralytics.nn.tasks.DetectionModel | 19 | add state-only | `nn/tasks.py:494`. `BaseModel` (`:121`) is a plain nn.Module. The `end2end` setter (`:567`) does not run on load because Module.__setstate__ uses `__dict__.update`. |
| ultralytics.nn.tasks.SegmentationModel | 3 | add state-only | `nn/tasks.py:687`. Subclass of DetectionModel, no hooks. |
| ultralytics.nn.tasks.ClassificationModel | 3 | add state-only | `nn/tasks.py:865`. No hooks. |
| ultralytics.nn.tasks.PoseModel | 2 | add state-only | `nn/tasks.py:795`. No hooks. |
| ultralytics.nn.modules.conv.Conv | 22 | add state-only | `nn/modules/conv.py:48`. No hooks. `forward = forward_fuse` exists only after fuse(); see section 4. |
| ultralytics.nn.modules.conv.Concat | 19 | add state-only | `conv.py:625`. No hooks. |
| ultralytics.nn.modules.conv.DWConv | 9 | add state-only | `conv.py:195`. Subclass of Conv. |
| ultralytics.nn.modules.conv.RepConv | 1 | add state-only | `conv.py:363`. No hooks. |
| ultralytics.nn.modules.block.Bottleneck | 21 | add state-only | `nn/modules/block.py:460`. No hooks. |
| ultralytics.nn.modules.block.SPPF | 18 | add state-only | `block.py:211`. No hooks. |
| ultralytics.nn.modules.block.DFL | 17 | add state-only | `block.py:60`. No hooks. |
| ultralytics.nn.modules.block.C2f | 13 | add state-only | `block.py:291`. No hooks. |
| ultralytics.nn.modules.block.C3k | 8 | add state-only | `block.py:1109` (subclass of C3, `:325`). No hooks. |
| ultralytics.nn.modules.block.C3k2 | 8 | add state-only | `block.py:1069`. No hooks. |
| ultralytics.nn.modules.block.C2PSA | 8 | add state-only | `block.py:1442`. No hooks. |
| ultralytics.nn.modules.block.PSABlock | 8 | add state-only | `block.py:1337`. No hooks. |
| ultralytics.nn.modules.block.Attention | 8 | add state-only | `block.py:1271`. No hooks. The only ultralytics `__setstate__` is on `AAttn` (`block.py:1650`/`1694`, sets a default), which is not on tune. |
| ultralytics.nn.modules.block.Proto | 2 | add state-only | `block.py:85`. No hooks. |
| ultralytics.nn.modules.block.AConv / ELAN1 / RepBottleneck / RepCSP / RepNCSPELAN4 / SPPELAN | 1 each | add state-only | `block.py:920`, `:900`, `:829`, `:848`, `:867`, `:964`. Plain nn.Modules, no hooks. |
| ultralytics.nn.modules.head.Detect | 16 | add state-only | `nn/modules/head.py:38`. Properties `one2many`/`one2one`/`end2end` (`:145-167`) are not run on load; the setter only logs and sets `_end2end`. |
| ultralytics.nn.modules.head.Segment | 2 | add state-only | `head.py:298`. No hooks. In older checkpoints the state holds `getattr(Detect,'forward')`; see section 4. |
| ultralytics.nn.modules.head.Classify | 3 | add state-only | `head.py:872`. No hooks. |
| ultralytics.nn.modules.head.Pose | 2 | add state-only | `head.py:572`. No hooks. |
| ultralytics.nn.modules.{Conv, C2f, Concat, Bottleneck, DFL, Detect, SPPF} | 5 each | add state-only (exact pairs) | 8.0.50 `nn/modules.py:23, 181, 344, 120, 69, 381, 287`. Plain nn.Modules, no hooks in 8.0.50. In 8.4.182 these names are re-exported from `nn/modules/__init__.py` (lines 119-180), so they load the classes reviewed above. |
| ultralytics.nn.modules.Segment / Proto | 1 each | add state-only | 8.0.50 `nn/modules.py:433` and `:354`. Segment stores `self.detect = Detect.forward` (`:440`); see section 4. |
| ultralytics.utils.loss.BboxLoss | 2 | add state-only | `utils/loss.py:118`. nn.Module, no hooks. |
| ultralytics.utils.loss.DFLoss | 1 | add state-only | `loss.py:96`. nn.Module, no hooks. |
| ultralytics.utils.loss.v8DetectionLoss | 1 | add state-only | `loss.py:354`. Plain class: no `__setstate__`/`__setattr__`/properties. The state holds the BCE loss, hyp, assigner and tensors. |
| ultralytics.utils.loss.v8SegmentationLoss | 1 | add state-only | `loss.py:511`. Subclass of v8DetectionLoss, no hooks. |
| ultralytics.utils.loss.E2ELoss | 1 | add state-only | `loss.py:1277`. Plain class holding two v8DetectionLoss instances and floats. |
| ultralytics.utils.tal.TaskAlignedAssigner | 2 | add state-only | `utils/tal.py:14`. nn.Module, no hooks. |
| ultralytics.utils.IterableSimpleNamespace | 2 | leave out | `utils/__init__.py:324`. Subclass of `types.SimpleNamespace`, whose C `__reduce__` gives **`REDUCE cls()` + BUILD**, not NEWOBJ. I confirmed this with a stand-in; the current scanner says "is called (REDUCE with arguments ())". `SimpleNamespace()` and `__getattr__` (`:366`, only raises) are harmless, but the pair would need a new "no-argument call" check, which is the owner's decision. |
| ultralytics.yolo.utils.IterableSimpleNamespace | 5 | leave out | 8.0.50 `yolo/utils/__init__.py:105`. Same as above. The module no longer exists in 8.4.182. |
| xgboost.core.Booster | 19 | needs check (owner decision); leave out by default | See section 5: `__setstate__` passes raw file bytes to libxgboost's native parser. |
| xgboost.sklearn.XGBClassifier | 11 | add state-only | 3.4.1 `sklearn.py:1759` (1.5.2 `sklearn.py:1123`). No own pickling hooks: only `sklearn.base.BaseEstimator.__setstate__` (`compat.py:39`). Its `_Booster` value is still checked as Booster. |
| xgboost.sklearn.XGBRegressor | 8 | add state-only | 3.4.1 `sklearn.py:2052` (1.5.2 `:1467`). Same as XGBClassifier. |
| xgboost.compat.XGBoostLabelEncoder | 8 | add state-only | 1.5.2 `compat.py:69`: subclass of sklearn `LabelEncoder`, only `to_json`/`from_json`, no pickling hooks. It is gone in 3.4.1, where loading fails with AttributeError. |
| `__builtin__.getattr` | 2 | not an allowlist entry | Judged per use by `_check_getattr`; see section 4. |

Out of scope: accelerate, pandas, dabl, gymnasium, stable_baselines3, sklearn, keras and the other pairs not listed here. I did not review them.

## 4. getattr in Ultralytics checkpoints

On tune, `__builtin__.getattr` appears only in the two segmentation files: `Ultralytics/YOLO11/yolo11n-seg.pt` and `keremberke/yolov8m-building-segmentation/best.pt`. They come from two sources.

**getattr(ultralytics.nn.modules.head.Detect, 'forward')** (the Detect class itself)
- In 8.0.50, `Segment.__init__` runs `self.detect = Detect.forward` (`nn/modules.py:440`), storing the plain function. By 8.2.103 / 8.3.0 / 8.3.40 / 8.4.182 the attribute is gone; Segment calls `Detect.forward(self, x)` directly (8.3.40 `head.py:194`).
- Checkpoints first created with old versions keep `detect` in `Segment.__dict__`.
- At protocol < 4, pickle saves a function with a dotted qualname as `getattr(<parent class GLOBAL>, 'forward')`. The name is fixed ('forward'), the result is stored and never called while loading.

**getattr(<instance>, 'forward_fuse')** (a bound method)
- `BaseModel.fuse()` runs `m.forward = m.forward_fuse` (`nn/tasks.py:265`); Conv2 does the same in `fuse_convs` (`conv.py:156`); `BNContrastiveHead.fuse()` runs `self.forward = self.forward_fuse` (`block.py:805`).
- A bound method pickles as `getattr(<instance>, 'forward_fuse')`. The name is fixed, the result is stored, not called.
- In 8.4.182, `BNContrastiveHead.forward_fuse` is a `@staticmethod` (`block.py:807`). So a checkpoint fused by 8.4.x pickles it as `getattr(<BNContrastiveHead class>, 'forward_fuse')`, the class form, not the instance form.
- BNContrastiveHead does not appear on tune, so I do not propose it.

**Would the current rule accept these once the classes are allowlisted?** I tested this in-process with stand-in classes, and with STATE_ONLY_CLASSES / ARGUMENT_CHECKED / PICKLE_GLOBALS patched only in memory; no file was edited.
- **Instance form** `getattr(<allowlisted instance>, 'forward_fuse')`: **accepted** (static_risk `clean`). `_getattr_target_ok` resolves the class through `class_of`. The value walk does not enter an Obj.
- **Class form** `getattr(Detect, 'forward')`: `_check_getattr` itself passes it, because a state-only pair is in `allow`. But `_check_guarded_calls` still walks getattr's arguments (`pickle_static.py:456`). A STATE_ONLY class is `_guarded`, so the scan reports "ultralytics.nn.modules.head.Detect is passed as a value at … (REDUCE); it may only be called directly", and static_risk is `suspicious`.
- So the two segmentation files on tune stay flagged even after Detect and Segment are added. Accepting them would need the owner to decide on a narrow exemption: a STATE_ONLY class as the first argument of a getattr call that `_check_getattr` already judged CLEAN, i.e. a public constant name whose result is never called. I recommend not changing this without that decision.

## 5. xgboost

- `Booster.__setstate__` (3.4.1 `core.py:1894`; the same in 1.5.2 `core.py:1440`) takes `state["handle"]` and, when it is not None, does the following:
  1. `XGBoosterCreate`;
  2. `(ctypes.c_char * len(buf)).from_buffer(buf)` (needs a writable buffer such as a bytearray);
  3. `XGBoosterUnserializeFromBuffer(handle, ptr, length)`, i.e. the attacker's bytes go to libxgboost's native C++ model/config parser;
  4. it replaces `handle` with the new pointer and runs `self.__dict__.update(state)`.
- The state cannot inject a raw handle value: any non-None handle is replaced, or a TypeError is raised first. `__del__` (`core.py:1873`) frees only that handle.
- No Python code is chosen by the file. The risk is the memory safety of a native parser fed untrusted bytes, which a static scan cannot verify.
- The pickle form is NEWOBJ `()` + BUILD (no `__reduce__`), so it would technically pass the state-only check.
- Recommendation: do not add Booster to STATE_ONLY_CLASSES silently. If the owner accepts "native libxgboost parser is trusted" (comparable to trusting torch's storage loader), add it with that comment and a regression test. Otherwise leave it out and keep these files UNVERIFIABLE/SUSPICIOUS.
- XGBClassifier, XGBRegressor and XGBoostLabelEncoder are safe on their own (BaseEstimator `__setstate__` only), but a real model always holds a Booster.

## 6. Recommended state-only pairs (copy-paste)

```python
    # torch 2.11.0 source: nn.Module pickles as NEWOBJ () + BUILD (protocol 2, no __reduce__);
    # Module.__setstate__ = __dict__.update + empty hook-dict defaults (module.py:1925)
    ("torch.nn.modules.activation", "SiLU"),
    ("torch.nn.modules.container", "ModuleList"),
    ("torch.nn.modules.container", "Sequential"),
    ("torch.nn.modules.batchnorm", "BatchNorm2d"),
    ("torch.nn.modules.conv", "Conv2d"),
    ("torch.nn.modules.conv", "ConvTranspose2d"),
    ("torch.nn.modules.pooling", "MaxPool2d"),
    ("torch.nn.modules.pooling", "AdaptiveAvgPool2d"),
    ("torch.nn.modules.upsampling", "Upsample"),
    ("torch.nn.modules.linear", "Identity"),
    ("torch.nn.modules.linear", "Linear"),
    ("torch.nn.modules.dropout", "Dropout"),
    ("torch.nn.modules.loss", "BCEWithLogitsLoss"),
    # torchvision 0.26.0
    ("torchvision.transforms.transforms", "Compose"),
    ("torchvision.transforms.transforms", "ToTensor"),
    ("torchvision.transforms.transforms", "Normalize"),
    ("torchvision.transforms.transforms", "Resize"),
    ("torchvision.transforms.transforms", "CenterCrop"),
    # ultralytics 8.4.182 (and 8.0.50 for the ultralytics.nn.modules.<Name> paths)
    ("ultralytics.nn.tasks", "DetectionModel"),
    ("ultralytics.nn.tasks", "SegmentationModel"),
    ("ultralytics.nn.tasks", "ClassificationModel"),
    ("ultralytics.nn.tasks", "PoseModel"),
    ("ultralytics.nn.modules.conv", "Conv"),
    ("ultralytics.nn.modules.conv", "Concat"),
    ("ultralytics.nn.modules.conv", "DWConv"),
    ("ultralytics.nn.modules.conv", "RepConv"),
    ("ultralytics.nn.modules.block", "Bottleneck"),
    ("ultralytics.nn.modules.block", "SPPF"),
    ("ultralytics.nn.modules.block", "DFL"),
    ("ultralytics.nn.modules.block", "C2f"),
    ("ultralytics.nn.modules.block", "C3k"),
    ("ultralytics.nn.modules.block", "C3k2"),
    ("ultralytics.nn.modules.block", "C2PSA"),
    ("ultralytics.nn.modules.block", "PSABlock"),
    ("ultralytics.nn.modules.block", "Attention"),
    ("ultralytics.nn.modules.block", "Proto"),
    ("ultralytics.nn.modules.block", "AConv"),
    ("ultralytics.nn.modules.block", "ELAN1"),
    ("ultralytics.nn.modules.block", "RepBottleneck"),
    ("ultralytics.nn.modules.block", "RepCSP"),
    ("ultralytics.nn.modules.block", "RepNCSPELAN4"),
    ("ultralytics.nn.modules.block", "SPPELAN"),
    ("ultralytics.nn.modules.head", "Detect"),
    ("ultralytics.nn.modules.head", "Segment"),
    ("ultralytics.nn.modules.head", "Classify"),
    ("ultralytics.nn.modules.head", "Pose"),
    ("ultralytics.nn.modules", "Conv"),
    ("ultralytics.nn.modules", "C2f"),
    ("ultralytics.nn.modules", "Concat"),
    ("ultralytics.nn.modules", "Bottleneck"),
    ("ultralytics.nn.modules", "DFL"),
    ("ultralytics.nn.modules", "Detect"),
    ("ultralytics.nn.modules", "SPPF"),
    ("ultralytics.nn.modules", "Segment"),
    ("ultralytics.nn.modules", "Proto"),
    ("ultralytics.utils.loss", "BboxLoss"),
    ("ultralytics.utils.loss", "DFLoss"),
    ("ultralytics.utils.loss", "v8DetectionLoss"),
    ("ultralytics.utils.loss", "v8SegmentationLoss"),
    ("ultralytics.utils.loss", "E2ELoss"),
    ("ultralytics.utils.tal", "TaskAlignedAssigner"),
    # xgboost (BaseEstimator.__setstate__ only; useful only if Booster is decided)
    ("xgboost.sklearn", "XGBClassifier"),
    ("xgboost.sklearn", "XGBRegressor"),
    ("xgboost.compat", "XGBoostLabelEncoder"),
```

Not state-only, for the owner to decide:
- ENUM_CLASSES candidate: `("torchvision.transforms.functional", "InterpolationMode")`.
- Needs a new rule: `ultralytics.utils.IterableSimpleNamespace` and `ultralytics.yolo.utils.IterableSimpleNamespace` (REDUCE `cls()`); the getattr-on-a-state-only-class exemption (section 4).
- Policy decision: `xgboost.core.Booster`.
- Left out: RNN, lazy and parametrized modules, BNContrastiveHead, AAttn (not on tune).
