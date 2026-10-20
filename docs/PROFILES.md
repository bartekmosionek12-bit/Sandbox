# Profiles for well-known files

A profile describes one kind of file that a known producer writes, so that safeloadai can
accept what that file needs **only where the producer puts it**. Profiles live in
`src/safeloadai/profiles/registry.py`. Each one is written by hand from the producer's
source, reviewed and committed; nothing is added at run time.

A profile has:

- a file-name pattern (exact, case-sensitive, matched against the base name);
- the producer, and the producer versions whose source confirmed the structure;
- the globals it accepts beyond the default rules, each at a fixed position;
- a structural check of the whole pickle.

## What a profile does

| file name | producer signature | structure | result |
|---|---|---|---|
| matches | present | matches | the profile's globals are accepted at their positions (`Report.cleared`, mechanism `profile`); the static report names the profile (`profile`, and a note) |
| matches | present | does not match | no profile; a RISKY reason: "file name matches the ... profile, but its structure does not: ..." |
| matches | absent | any | nothing changes |
| does not match | any | any | nothing changes |

A profile never lowers other evidence. Everything else in the file is judged by the usual
rules: a sink stays MALICIOUS, an unknown global stays UNVERIFIABLE, a RISKY finding stays
RISKY. An accepted global must be rebuilt exactly as the producer writes it (`NEWOBJ` with
no arguments, then exactly one `BUILD` with a dict state). It must not be passed to a call,
receive `SETITEM`/`APPEND`, be used as a dict key, appear at a second position or be
constructed anywhere else. Anything else is a structure mismatch.

## Shipped profiles

### `transformers-training-args`: `training_args.bin`

`Trainer._save` writes `torch.save(self.args, "training_args.bin")`. The structure is a
`TrainingArguments` (or a subclass) rebuilt from a dict state. Source read: transformers
5.20.2 (`training_args.py`, `trainer.py`) and accelerate 1.15.0 (`state.py`).

| global | allowed position | review |
|---|---|---|
| `accelerate.state.PartialState` | `root.distributed_state` | Defines no `__new__`, `__setstate__`, `__reduce__` or property setter. Its only hook, `__getattr__`, raises `AttributeError`. `NEWOBJ ()` + `BUILD` stores the dict in the new instance's own `__dict__`; `__init__`, which would set up distributed state, does not run. `accelerate.state` is an inert module. |
| `transformers.trainer_pt_utils.AcceleratorConfig` | `root.accelerator_config` | A `@dataclass` with no hooks (state-only by the Part 2 analysis). Its module runs `@smp.step` decorators only when SageMaker model parallelism is enabled, which importing `transformers.Trainer` runs anyway. |

The root class is not accepted by the profile. `TrainingArguments` is on the default
allowlist; a subclass from another package (trl `SFTConfig`, llava, ...) stays UNVERIFIABLE.

### `transformers-optimizer`, `transformers-scheduler`, `transformers-rng-state`

These cover `optimizer.pt`, `scheduler.pt`, `rng_state.pth` and `rng_state_*.pth`.
Trainer writes plain state dicts in them. The default rules accept everything inside, so
these profiles accept nothing extra. A file with one of these names that is not shaped like
one is RISKY:

- `optimizer.pt` must be `{"state", "param_groups"}`;
- `scheduler.pt` must be a dict with `last_epoch`;
- an RNG state must have the keys `python`, `numpy` and `cpu`, plus only device keys
  (`cuda`, `xla`, `npu`, `hpu`, `mlu`, `musa`, `xpu`, `mps`).

### `ultralytics-checkpoint`: `*.pt` with an `ultralytics.*` import

`BaseTrainer.save_model` and `strip_optimizer` write a dict. The keys were confirmed from
the ultralytics 8.0.100, 8.1.0, 8.2.0, 8.3.0 and 8.4.182 sources:

`epoch`, `best_fitness`, `stopper`, `model`, `ema`, `updates`, `modelopt`, `optimizer`,
`scaler`, `train_args`, `train_metrics`, `train_results`, `date`, `version`, `git`,
`license`, `docs`.

`model` must be present. `model` and `ema` hold an `ultralytics.nn.tasks` model rebuilt from
a dict state, or None. No `ultralytics.nn.tasks` model may appear anywhere else. The model
classes themselves are judged by the default rules (the allowlist and the Part 2 policies).
The profile adds the key and position constraints, so an Ultralytics checkpoint with an
extra key is RISKY. Because `*.pt` is a generic name, the profile is engaged only when the
stream imports an `ultralytics.*` global.

## Tune split

All 81 tune files whose names match a profile were checked, and none mismatched. The
`training_args.bin` profile accepts `PartialState` in 17 tune files and `AcceleratorConfig`
in 6. Files with root classes from other packages (trl, yart, llava) or with DeepSpeed
configs stay UNVERIFIABLE.
