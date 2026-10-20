"""The shipped profiles (reviewed by hand; see docs/PROFILES.md for the review notes)."""
from __future__ import annotations

from ..static.pickle_vm import Obj, class_of
from . import Profile, rebuilt_instance, str_keyed_dict, stray

# --- transformers Trainer ---------------------------------------------------------------
#
# Trainer._save writes ``torch.save(self.args, "training_args.bin")``: a TrainingArguments
# (or a subclass, possibly from another package) rebuilt by NEWOBJ () + a dict BUILD. Since
# transformers 4.3x its dict state holds two objects the default rules do not accept:
#
# * ``distributed_state``: accelerate.state.PartialState, set by
#   TrainingArguments._setup_devices. PartialState defines no __new__, __setstate__,
#   __reduce__ or property setter; its only hook, __getattr__, raises AttributeError
#   (accelerate 1.15.0 accelerate/state.py, read with ast). Rebuilding it stores the dict
#   into the new instance's own __dict__ (its __init__, which shares state between
#   instances, does not run). accelerate.state is an inert module (upstream data).
# * ``accelerator_config``: transformers.trainer_pt_utils.AcceleratorConfig, a @dataclass
#   with no hooks (state-only by the Part 2 analysis). Its module is not inert only because
#   of SageMaker-gated decorators (``if is_sagemaker_mp_enabled(): @smp.step``), which is
#   what importing transformers.Trainer runs in any case.
#
# The root class itself is not cleared here: TrainingArguments is on the default allowlist
# and a subclass from another package (trl, llava, ...) stays UNVERIFIABLE.

PARTIAL_STATE = ("accelerate.state", "PartialState")
ACCELERATOR_CONFIG = ("transformers.trainer_pt_utils", "AcceleratorConfig")
_TRAINING_ARGS_POSITIONS = {"distributed_state": PARTIAL_STATE, "accelerator_config": ACCELERATOR_CONFIG}


def _beyond_weights_only(imports: list[dict]) -> bool:
    """The producer signature of training_args.bin: an import torch's weights-only loader
    would refuse. A stream whose every import that loader accepts (a plain dict of
    arguments, say) needs nothing from the profile and is left to the default rules."""
    from ..static.upstream import torch_weights_only as wo

    return any(i.get("module") is None or f"{i['module']}.{i.get('symbol')}" not in wo.ALLOWED for i in imports)


def _training_args(root):
    if not rebuilt_instance(root):
        return {}, "the root is not an object rebuilt from a dict state (NEWOBJ () + BUILD)"
    accepted = {}
    for key, pair in _TRAINING_ARGS_POSITIONS.items():
        value = root.state.get(key)
        if isinstance(value, Obj) and class_of(value) == pair:
            if not rebuilt_instance(value):
                return {}, f"{key} is not rebuilt from a dict state"
            accepted[id(value)] = (value, root)
    return accepted, stray(TRAINING_ARGS, root, accepted)


TRAINING_ARGS = Profile(
    name="transformers-training-args",
    producer="transformers Trainer (torch.save(self.args))",
    patterns=("training_args.bin",),
    source="transformers 5.20.2 training_args.py/trainer.py, accelerate 1.15.0 state.py",
    check=_training_args,
    clears={PARTIAL_STATE: "TrainingArguments.distributed_state (accelerate PartialState, no hooks but a "
                           "raising __getattr__)",
            ACCELERATOR_CONFIG: "TrainingArguments.accelerator_config (a hook-free dataclass)"},
    engaged=_beyond_weights_only,
)


# Trainer._save_optimizer_and_scheduler / _save_rng_state write plain state dicts. The
# default rules accept everything they contain, so these profiles accept nothing extra:
# they only make a file with one of these names that is not shaped like one RISKY.

def _optimizer(root):
    if not (str_keyed_dict(root) and set(root) == {"state", "param_groups"}):
        return {}, "the root is not an optimizer state_dict ({'state', 'param_groups'})"
    return {}, None


def _scheduler(root):
    if not (str_keyed_dict(root) and "last_epoch" in root):
        return {}, "the root is not an LR scheduler state_dict (a dict with 'last_epoch')"
    return {}, None


RNG_KEYS = frozenset({"python", "numpy", "cpu", "cuda", "xla", "npu", "hpu", "mlu", "musa", "xpu", "mps"})


def _rng_state(root):
    if not (str_keyed_dict(root) and {"python", "numpy", "cpu"} <= set(root) <= RNG_KEYS):
        return {}, f"the root is not a Trainer RNG state (keys python, numpy, cpu and devices from {sorted(RNG_KEYS)})"
    return {}, None


OPTIMIZER = Profile(name="transformers-optimizer", producer="transformers Trainer (optimizer.state_dict())",
                    patterns=("optimizer.pt",), source="transformers 5.20.2 trainer.py", check=_optimizer)
SCHEDULER = Profile(name="transformers-scheduler", producer="transformers Trainer (lr_scheduler.state_dict())",
                    patterns=("scheduler.pt",), source="transformers 5.20.2 trainer.py", check=_scheduler)
RNG_STATE = Profile(name="transformers-rng-state", producer="transformers Trainer (_save_rng_state)",
                    patterns=("rng_state.pth", "rng_state_*.pth"), source="transformers 5.20.2 trainer.py",
                    check=_rng_state)


# --- Ultralytics ------------------------------------------------------------------------
#
# BaseTrainer.save_model and strip_optimizer write a dict. Keys confirmed from the
# ultralytics 8.0.100, 8.1.0, 8.2.0, 8.3.0 and 8.4.182 sources; ``model`` and ``ema`` hold
# the model (an ultralytics.nn.tasks class, rebuilt by NEWOBJ () + BUILD) or None. The
# classes themselves are judged by the default rules (allowlist and Part 2 policies); the
# profile constrains where a model may appear and which keys the dict may have.

ULTRALYTICS_KEYS = frozenset({"epoch", "best_fitness", "stopper", "model", "ema", "updates", "modelopt",
                              "optimizer", "scaler", "train_args", "train_metrics", "train_results", "date",
                              "version", "git", "license", "docs"})
_TASKS = ("ultralytics.nn.tasks",)


def _ultralytics_model(pair) -> bool:
    return pair[0] in _TASKS


def _ultralytics(root):
    if not str_keyed_dict(root):
        return {}, "the root is not a dict with str keys"
    extra = sorted(set(root) - ULTRALYTICS_KEYS)
    if extra:
        return {}, f"keys outside an Ultralytics checkpoint: {', '.join(map(repr, extra[:5]))}"
    if "model" not in root:
        return {}, "no 'model' key"
    accepted = {}
    for key in ("model", "ema"):
        value = root.get(key)
        if value is None:
            continue
        pair = class_of(value)
        if not (pair and _ultralytics_model(pair) and rebuilt_instance(value)):
            return {}, f"{key!r} is not an ultralytics.nn.tasks model rebuilt from a dict state"
        accepted[id(value)] = (value, None)
    return accepted, stray(ULTRALYTICS, root, accepted)


ULTRALYTICS = Profile(
    name="ultralytics-checkpoint",
    producer="Ultralytics (BaseTrainer.save_model, strip_optimizer)",
    patterns=("*.pt",),
    source="ultralytics 8.0.100, 8.1.0, 8.2.0, 8.3.0, 8.4.182 engine/trainer.py and utils/torch_utils.py",
    check=_ultralytics,
    placed=_ultralytics_model,
    engaged=lambda imports: any((i.get("module") or "").startswith("ultralytics.") for i in imports),
)

# Most specific names first: a file named optimizer.pt is the Trainer's, not Ultralytics'.
PROFILES = (TRAINING_ARGS, OPTIMIZER, SCHEDULER, RNG_STATE, ULTRALYTICS)
