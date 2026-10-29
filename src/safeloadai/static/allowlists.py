"""Allowlists. Exact matches only: no prefixes, no wildcards, no name-shape rules.

Every pickle entry is a ``(module, qualname)`` pair exactly as it appears in a
GLOBAL / STACK_GLOBAL / INST opcode. Anything not listed here makes a file at
least SUSPICIOUS, because ``find_class`` imports the module even if the object
is never called.

Where each entry comes from is written next to it. "tuning corpus" means the
pickles produced by ``tools/eval_static.py:benign_corpus`` (numpy 2.5.4,
scikit-learn 1.9.1); its hold-out corpus is deliberately NOT used here, so the
false-positive rate measured on it stays honest. Entries that come from reading
a framework's own allowlist rather than from a file we produced are marked
"unverified" until the benign corpus (milestone 6) confirms them.
"""
from __future__ import annotations

from . import upstream as _upstream

# --- pickle -----------------------------------------------------------------

_BUILTIN_TYPES = (
    "set", "frozenset", "bytearray", "bytes", "complex", "slice", "range",
    "list", "dict", "tuple", "int", "float", "str", "bool",
)

PICKLE_GLOBALS: frozenset[tuple[str, str]] = frozenset(
    # Protocol 0-2 rebuild these builtins through GLOBAL (tuning corpus: set,
    # frozenset, bytes, complex; the rest are the same constructor family).
    [("builtins", t) for t in _BUILTIN_TYPES]
    + [("__builtin__", t) for t in _BUILTIN_TYPES]
    + [
        # Protocol 0-2 object reconstruction (copyreg is what pickle itself emits).
        ("copyreg", "_reconstructor"),
        ("copy_reg", "_reconstructor"),
        ("_codecs", "encode"),  # bytes in protocol 2 (tuning corpus)
        ("collections", "OrderedDict"),
        # numpy arrays and scalars (tuning corpus; numpy.core.* is the same
        # function under numpy < 2)
        ("numpy", "dtype"),
        ("numpy", "ndarray"),
        ("numpy._core.multiarray", "_reconstruct"),
        ("numpy._core.multiarray", "scalar"),
        ("numpy._core.numeric", "_frombuffer"),
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy.core.multiarray", "scalar"),
        ("numpy.core.numeric", "_frombuffer"),
        # numpy random state inside estimators (tuning corpus)
        ("numpy.random._mt19937", "MT19937"),
        ("numpy.random._pickle", "__bit_generator_ctor"),
        ("numpy.random._pickle", "__randomstate_ctor"),
        ("numpy.random.bit_generator", "SeedSequence"),
        ("numpy.random.bit_generator", "__pyx_unpickle_SeedSequence"),
        # joblib's placeholder for an ndarray whose raw bytes follow it in the stream.
        # A plain data holder (no __reduce__/__setstate__, no code on construction);
        # the scanner reads its layout exactly (shared/joblib_layout.py) and the
        # safe_load loader maps it to its own reader, never importing joblib.
        ("joblib.numpy_pickle", "NumpyArrayWrapper"),
        # scikit-learn estimators and their internals (tuning corpus)
        ("sklearn._loss._loss", "CyHalfMultinomialLoss"),
        ("sklearn._loss._loss", "__pyx_unpickle_CyHalfMultinomialLoss"),
        ("sklearn._loss.link", "Interval"),
        ("sklearn._loss.link", "MultinomialLogit"),
        ("sklearn._loss.loss", "HalfMultinomialLoss"),
        ("sklearn.cluster._kmeans", "KMeans"),
        ("sklearn.decomposition._pca", "PCA"),
        ("sklearn.dummy", "DummyClassifier"),
        ("sklearn.ensemble._forest", "RandomForestClassifier"),
        ("sklearn.ensemble._gb", "GradientBoostingClassifier"),
        ("sklearn.linear_model._base", "LinearRegression"),
        ("sklearn.linear_model._logistic", "LogisticRegression"),
        ("sklearn.metrics._dist_metrics", "EuclideanDistance64"),
        ("sklearn.metrics._dist_metrics", "newObj"),
        ("sklearn.naive_bayes", "GaussianNB"),
        ("sklearn.neighbors._classification", "KNeighborsClassifier"),
        ("sklearn.neighbors._kd_tree", "KDTree"),
        ("sklearn.neighbors._kd_tree", "newObj"),
        ("sklearn.pipeline", "Pipeline"),
        ("sklearn.preprocessing._data", "StandardScaler"),
        ("sklearn.svm._classes", "SVC"),
        ("sklearn.tree._classes", "DecisionTreeClassifier"),
        ("sklearn.tree._classes", "DecisionTreeRegressor"),
        ("sklearn.tree._tree", "Tree"),
        # Added after the 2026-10-18 false-positive review
        # (evaluation/results/false-positives-20261018.md). One justification per pair.
        ("numpy", "float64"),  # scalar type used as a dtype parameter; calling it returns a float or raises
        ("numpy.random._pcg64", "PCG64"),  # bit-generator class; its state is a dict of integers
        ("numpy.random._pickle", "__generator_ctor"),  # only with the argument check in GUARDED_CALLS
        ("sklearn._loss._loss", "CyHalfBinomialLoss"),  # Cython loss without constructor arguments
        ("sklearn._loss._loss", "CyHalfSquaredError"),  # Cython loss without constructor arguments
        ("sklearn._loss.link", "IdentityLink"),  # stateless link class
        ("sklearn._loss.link", "LogitLink"),  # stateless link class
        ("sklearn._loss.loss", "HalfBinomialLoss"),  # Python loss; constructor arguments are numbers
        ("sklearn._loss.loss", "HalfSquaredError"),  # Python loss; constructor arguments are numbers
        # restores __dict__ only; each transformer it names is checked as its own global
        # (FunctionTransformer, which holds an arbitrary function, stays out)
        ("sklearn.compose._column_transformer", "ColumnTransformer"),
        ("sklearn.dummy", "DummyRegressor"),  # plain estimator (GradientBoostingRegressor init model)
        ("sklearn.ensemble._gb", "GradientBoostingRegressor"),  # plain estimator
        ("sklearn.ensemble._hist_gradient_boosting.binning", "_BinMapper"),  # plain estimator
        # plain estimator
        ("sklearn.ensemble._hist_gradient_boosting.gradient_boosting", "HistGradientBoostingClassifier"),
        ("sklearn.ensemble._hist_gradient_boosting.predictor", "TreePredictor"),  # holds node arrays
        # restores __dict__; a custom tokenizer/preprocessor/analyzer is a global of its own, still checked
        ("sklearn.feature_extraction.text", "TfidfVectorizer"),
        ("sklearn.feature_extraction.text", "TfidfTransformer"),  # plain estimator
        ("sklearn.linear_model._ridge", "Ridge"),  # plain estimator
        ("sklearn.linear_model._sgd_fast", "Hinge"),  # Cython loss; __reduce__ is (Hinge, (threshold,))
        ("sklearn.linear_model._stochastic_gradient", "SGDClassifier"),  # BaseEstimator.__setstate__ only
        ("sklearn.neural_network._multilayer_perceptron", "MLPClassifier"),  # plain estimator
        ("sklearn.neural_network._stochastic_optimizers", "AdamOptimizer"),  # holds arrays and floats
        ("sklearn.preprocessing._encoders", "OneHotEncoder"),  # plain estimator
        ("sklearn.preprocessing._label", "LabelBinarizer"),  # plain estimator
        ("sklearn.preprocessing._label", "LabelEncoder"),  # plain estimator (classes_ array)
        # 2026-10-19 review: Cython unpickle helper, same as the CyHalfMultinomialLoss one above
        ("sklearn._loss._loss", "__pyx_unpickle_CyHalfBinomialLoss"),
        # 0.10.0 review (scikit-learn 1.5.1-1.9.1 _loss.pyx.tp): CyPinballLoss(quantile) is
        # __reduce__ (cls, (quantile,)) since 1.6 and the Cython unpickle helper before; the
        # constructor takes one double. Also reachable as _loss.* (static/sklearn_loss.py)
        ("sklearn._loss._loss", "CyPinballLoss"),
        ("sklearn._loss._loss", "__pyx_unpickle_CyPinballLoss"),
        # the type object and numpy's abstract scalar type, as values (copyreg._reconstructor's
        # base, make_column_selector's dtype_exclude); calling either makes a bare object or raises
        ("builtins", "object"),
        ("__builtin__", "object"),
        ("numpy", "number"),
    ]
)

# numpy's pickling helpers that call one of their arguments: __generator_ctor(name, ctor)
# and __randomstate_ctor(name, ctor) return ctor(name), and __bit_generator_ctor(cls)
# returns cls(). Each is a call primitive, so each allowed pair above is accepted only
# when every call matches numpy's own pickles (pickle_static._check_guarded_calls):
# the first argument a numpy bit-generator name, class or instance, the ctor argument
# absent or __bit_generator_ctor, and the function never passed around as a value.
NUMPY_BIT_GENERATOR_CTOR = ("numpy.random._pickle", "__bit_generator_ctor")
NUMPY_BIT_GENERATOR_NAMES = frozenset({"MT19937", "PCG64", "PCG64DXSM", "Philox", "SFC64"})
NUMPY_BIT_GENERATOR_CLASSES = frozenset({
    ("numpy.random._mt19937", "MT19937"),
    ("numpy.random._pcg64", "PCG64"),
    ("numpy.random._pcg64", "PCG64DXSM"),
    ("numpy.random._philox", "Philox"),
    ("numpy.random._sfc64", "SFC64"),
})
GUARDED_CALLS = frozenset({
    ("numpy.random._pickle", "__generator_ctor"),
    ("numpy.random._pickle", "__randomstate_ctor"),
    NUMPY_BIT_GENERATOR_CTOR,
})

# --- pairs that pass only with an argument check (2026-10-19 review) --------------------
# evaluation/results/allowlist-review-20261019.md; enforced by
# pickle_static._check_guarded_calls, with a regression test per check in
# tests/test_allowlist_review_20261019.py.

# Classes accepted only when the stream rebuilds an instance from its saved state without
# calling the class: NEWOBJ with no arguments (how protocol 2+ saves a plain object), then
# BUILD. Only cls.__new__ (object.__new__ for all of these) and then __setstate__ or a
# __dict__ update run. Every value in the state is checked as its own global, and nothing
# in it is called while loading. Calling the class (REDUCE, OBJ, INST, NEWOBJ with
# arguments) would run its constructor, so it is refused, and so is passing the class
# around as a value.
STATE_ONLY_CLASSES = frozenset({
    # scipy 1.18 sparse matrices define no __reduce__/__setstate__ (checked in the source)
    ("scipy.sparse._csr", "csr_matrix"),
    # pandas Index: only as the class argument of _new_Index (PANDAS_NEW_INDEX below)
    ("pandas.core.indexes.base", "Index"),
    ("pandas.core.indexes.range", "RangeIndex"),
    ("pandas", "RangeIndex"),
    # scikit-learn 1.9.1 estimators: BaseEstimator.__setstate__ only (version warning,
    # then a __dict__ update); constructors only store their parameters
    ("sklearn.calibration", "CalibratedClassifierCV"),
    ("sklearn.calibration", "_CalibratedClassifier"),
    ("sklearn.calibration", "_SigmoidCalibration"),
    ("sklearn.ensemble._forest", "RandomForestRegressor"),
    ("sklearn.impute._base", "SimpleImputer"),
    ("sklearn.linear_model._coordinate_descent", "Lasso"),
    ("sklearn.naive_bayes", "MultinomialNB"),
    ("sklearn.svm._classes", "LinearSVC"),
    ("sklearn.impute._base", "MissingIndicator"),
    ("sklearn.linear_model._logistic", "LogisticRegressionCV"),
    ("sklearn.model_selection._search_successive_halving", "HalvingGridSearchCV"),  # holds an estimator
    ("sklearn.model_selection._split", "StratifiedKFold"),
    ("sklearn.preprocessing._data", "MinMaxScaler"),
    ("sklearn.preprocessing._encoders", "OrdinalEncoder"),
    ("sklearn.tree._classes", "ExtraTreeRegressor"),
    # sklearn 1.9.1: __init__ stores pattern / dtype_include / dtype_exclude; no pickling hooks
    ("sklearn.compose._column_transformer", "make_column_selector"),
    # 0.10.0 review (evaluation/results/source-review-0.10.0.md; scikit-learn 1.5.1, 1.6.1, 1.7.2,
    # 1.8.0 and 1.9.1 sources): pickled as NEWOBJ () + BUILD.
    # HistGradientBoostingRegressor: no hooks of its own or in BaseHistGradientBoosting, so
    # BaseEstimator.__setstate__ (as for the classifier above)
    ("sklearn.ensemble._hist_gradient_boosting.gradient_boosting", "HistGradientBoostingRegressor"),
    # _RemainderColsList (1.5 and 1.6 only): a collections.UserList with three plain attributes
    # (future_dtype, warning_was_emitted, warning_enabled); neither it nor UserList defines a
    # pickling hook, __setattr__ or __getattr__, so BUILD is a __dict__ update
    ("sklearn.compose._column_transformer", "_RemainderColsList"),
    # Bunch: a dict subclass; its items come back through dict.__setitem__ (SETITEMS, not
    # overridden) and its __setstate__ is a no-op that ignores the state
    ("sklearn.utils._bunch", "Bunch"),
    # Training-argument dataclasses of public fine-tuning libraries (training_args.bin), 0.10.0
    # review of the PyPI sources (llamafactory 0.9.5, FlagEmbedding 1.2.11 and 1.4.2, ms-swift
    # 3.2.0 and 3.8.0, axolotl 0.6.0, 0.8.0 and 0.21.1; read with ast, never imported): each is
    # @dataclass over transformers' TrainingArguments / trl's configs (reviewed above) and
    # dataclass mixins, with no __setstate__, __reduce__, __getstate__, __setattr__, __getattr__
    # or property setters anywhere in its own classes. Unpickling is object.__new__ plus a
    # __dict__ update; __post_init__ (llamafactory's reads Ray settings) never runs.
    ("llamafactory.hparams.training_args", "TrainingArguments"),
    ("FlagEmbedding.baai_general_embedding.finetune.arguments", "RetrieverTrainingArguments"),
    ("FlagEmbedding.finetune.embedder.encoder_only.m3.arguments", "EncoderOnlyEmbedderM3TrainingArguments"),
    ("swift.trainers.rlhf_arguments", "GRPOConfig"),
    ("axolotl.core.trainer_builder", "AxolotlTrainingArguments"),
    ("axolotl.core.training_args", "AxolotlTrainingArguments"),
    # lightgbm 3.3.5 and 4.7.0 sklearn.py: LGBMModel and its classifier/regressor define no
    # pickling hooks; the base is scikit-learn's BaseEstimator. The Booster they hold is a
    # global of its own (UNVERIFIABLE, or --validate-boosters)
    ("lightgbm.sklearn", "LGBMClassifier"),
    ("lightgbm.sklearn", "LGBMRegressor"),
    # stdlib argparse.Namespace (an old training_args.bin): no pickling hooks, attributes only
    ("argparse", "Namespace"),
    # transformers' training arguments (training_args.bin): plain dataclasses. Rebuilt
    # from state, __post_init__ (which sets up devices and reads config files) never runs;
    # the fields are data, and an enum field is checked by ENUM_CLASSES. The owner checked
    # the transformers 4.30.0 and 5.20.1 sources (2026-10-19): @dataclass with no
    # __setstate__, __reduce__, __getstate__, __setattr__ or property setters, so unpickling
    # is object.__new__ plus a __dict__ update and __post_init__ is not called.
    ("transformers.training_args", "TrainingArguments"),
    ("transformers.training_args_seq2seq", "Seq2SeqTrainingArguments"),
    # 2026-10-19 source review (evaluation/results/allowlist-review-20261019.md, "Source review"):
    # sources read from PyPI wheels (torch 2.11.0, torchvision 0.26.0, ultralytics 8.4.182 and
    # 8.0.50, xgboost 3.4.1 and 1.5.2), never installed or imported. Only classes seen on the
    # tune half; no module prefix.
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
    # xgboost (BaseEstimator.__setstate__ only). Booster itself stays out: its __setstate__
    # feeds the raw bytes to libxgboost's native parser (owner's decision pending)
    ("xgboost.sklearn", "XGBClassifier"),
    ("xgboost.sklearn", "XGBRegressor"),
    ("xgboost.compat", "XGBoostLabelEncoder"),
})
# Enum classes, accepted only as cls(value) with one str or int argument: a member lookup.
ENUM_CLASSES = frozenset({
    ("transformers.trainer_utils", "IntervalStrategy"),
    ("transformers.trainer_utils", "SchedulerType"),
    ("transformers.trainer_utils", "HubStrategy"),
    ("transformers.trainer_utils", "SaveStrategy"),
    ("transformers.trainer_utils", "EvaluationStrategy"),
    ("transformers.training_args", "OptimizerNames"),
    ("accelerate.utils.dataclasses", "DistributedType"),
    # torchvision 0.26.0 functional.py: class InterpolationMode(Enum) with str values
    ("torchvision.transforms.functional", "InterpolationMode"),
    # 0.9.0 tune / tune-2 review (evaluation/results/source-review-4-20261023.md): bodies of
    # string constants only. sentence-transformers: ExplicitEnum (transformers.utils.generic:
    # str + Enum whose _missing_ raises ValueError), 3.0.0 to 5.3.0 in training_args, 6.2.0 in
    # base.sampler; trl: plain Enum in dpo_config, 0.9.6 to 0.28.0 (gone in 1.x).
    ("sentence_transformers.base.sampler", "BatchSamplers"),
    ("sentence_transformers.base.sampler", "MultiDatasetBatchSamplers"),
    ("sentence_transformers.training_args", "BatchSamplers"),
    ("sentence_transformers.training_args", "MultiDatasetBatchSamplers"),
    ("trl.trainer.dpo_config", "FDivergenceType"),
})
# pandas.core.indexes.base._new_Index(cls, d) returns cls.__new__(cls, **d): it calls its
# first argument. Accepted only as pandas writes it for a plain Index: _new_Index(Index,
# {"data": ..., "name": ...}) (pandas 3.0.5 Index.__reduce__). Other Index classes are not
# reviewed (their form was seen only in held-out files).
PANDAS_NEW_INDEX = ("pandas.core.indexes.base", "_new_Index")
# class -> the dict keys its __reduce__ writes
PANDAS_INDEX_KEYS = {
    ("pandas.core.indexes.base", "Index"): frozenset({"data", "name"}),
    # RangeIndex.__reduce__ writes {"name", "start", "stop", "step"} (pandas 1.4.4 range.py and
    # 3.1.0 range.py; 3.x names the class pandas.RangeIndex); _new_Index then calls
    # RangeIndex.__new__(cls, start=, stop=, step=, name=, copy=False), which only builds a
    # range. Accepted only with int start/stop/step (pickle_static._argument_check).
    ("pandas.core.indexes.range", "RangeIndex"): frozenset({"name", "start", "stop", "step"}),
    ("pandas", "RangeIndex"): frozenset({"name", "start", "stop", "step"}),
}
PANDAS_RANGE_INDEX = frozenset({("pandas.core.indexes.range", "RangeIndex"), ("pandas", "RangeIndex")})
PANDAS_INDEX_CLASSES = frozenset(PANDAS_INDEX_KEYS)
# collections.defaultdict(factory): the factory is called later, on a missing key, never
# while loading. Accepted with no factory or one imported global, which the allowlist
# checks like any other import (the owner's rule: "factory checked as global").
DEFAULTDICT = ("collections", "defaultdict")
# Classes pickled as REDUCE cls() + BUILD (a types.SimpleNamespace subclass: its C __reduce__
# returns (type(self), (), self.__dict__)). Accepted only as a call with an exactly empty
# argument tuple whose result goes only to a BUILD with a dict state, never to another call
# (owner's rule "zero-arg call", 2026-10-19). Each entry: reviewed source version and why.
ZERO_ARG_CLASSES = frozenset({
    # ultralytics 8.4.182 utils/__init__.py and 8.0.50 yolo/utils/__init__.py: SimpleNamespace
    # subclass adding __iter__, __str__, __getattr__ (raises AttributeError, also for
    # "__setstate__", which BUILD looks up) and get(); no __init__, __setattr__ or properties
    # (evaluation/results/source-review-2-20261019.md)
    ("ultralytics.utils", "IterableSimpleNamespace"),
    ("ultralytics.yolo.utils", "IterableSimpleNamespace"),
})

# --- pandas objects, dabl estimators and a scikit-learn scorer (Phase 5 tune review) ----
# evaluation/results/source-review-3-20261022.md: sources read from PyPI wheels and sdists
# (pandas 1.4.4 and 3.1.0, dabl 0.2.6.2 and 0.3.2, scikit-learn 1.1.3 and 1.9.1), never
# installed or imported. Enforced by pickle_static (_argument_check, _build_state_problem),
# with an adversarial test per entry in tests/test_allowlist_review_20261022.py. Each form
# below is the only one accepted; anything else stays SUSPICIOUS.
PANDAS_DATAFRAME = ("pandas.core.frame", "DataFrame")
PANDAS_SERIES = ("pandas.core.series", "Series")
PANDAS_BLOCK_MANAGER = ("pandas.core.internals.managers", "BlockManager")
PANDAS_SINGLE_BLOCK_MANAGER = ("pandas.core.internals.managers", "SingleBlockManager")
PANDAS_UNPICKLE_BLOCK = ("pandas._libs.internals", "_unpickle_block")
PANDAS_CATEGORICAL_DTYPE = ("pandas.core.dtypes.dtypes", "CategoricalDtype")
SKLEARN_THRESHOLD_SCORER = ("sklearn.metrics._scorer", "_ThresholdScorer")
# Score functions a scorer stores in _score_func: accepted only as that stored value,
# never called and never passed to a call while loading (the scorer calls it later).
SCORER_FUNCTIONS = frozenset({
    ("sklearn.metrics._ranking", "average_precision_score"),  # numeric metric, 1.1.3 and 1.9.1
})
# The keys each class's own __getstate__ writes; its __setstate__ (or __dict__ update) sets
# every key it is given, so a BUILD state with any other key is refused.
BUILD_STATE_KEYS = {
    # NDFrame.__getstate__/__setstate__ (pandas 1.4.4 generic.py:2107, 3.1.0 generic.py:2012):
    # _mgr, _typ, _metadata, attrs, _flags and one key per _metadata name (Series: "name").
    # __setstate__ sets each key with object.__setattr__ and builds Flags(self, **_flags).
    PANDAS_DATAFRAME: frozenset({"_mgr", "_typ", "_metadata", "attrs", "_flags"}),
    PANDAS_SERIES: frozenset({"_mgr", "_typ", "_metadata", "attrs", "_flags", "name"}),
    # CategoricalDtype.__setstate__ pops "categories" and "ordered" into private attributes
    # (pandas 1.4.4 dtypes.py:342, 3.1.0 dtypes.py:398)
    PANDAS_CATEGORICAL_DTYPE: frozenset({"categories", "ordered"}),
    # _BaseScorer.__init__(score_func, sign, kwargs) stores _score_func, _sign, _kwargs; no
    # pickling hooks (scikit-learn 1.1.3 metrics/_scorer.py:144; the class is gone in 1.9.1,
    # where importing it fails)
    SKLEARN_THRESHOLD_SCORER: frozenset({"_kwargs", "_score_func", "_sign"}),
}
PANDAS_STATE_ONLY = frozenset({
    # rebuilt by NEWOBJ () + BUILD; the state is checked against BUILD_STATE_KEYS and
    # pickle_static._build_state_problem (what each key may hold)
    PANDAS_DATAFRAME,
    PANDAS_SERIES,
    PANDAS_CATEGORICAL_DTYPE,
    # BaseBlockManager.__getstate__ writes (axes, values, items, {"0.14.1": {"axes": [...],
    # "blocks": [{"values", "mgr_locs"}]}}); __setstate__ reads only the "0.14.1" part, makes
    # each axis an Index (ensure_index) and each block with new_block(values, mgr_locs, ndim)
    # (pandas 1.4.4 managers.py:1764-1800, 3.1.0 managers.py:2118-2160). Accepted only with
    # that tuple state, numpy arrays as values and slices as block locations.
    PANDAS_SINGLE_BLOCK_MANAGER,
})
STATE_ONLY_CLASSES = STATE_ONLY_CLASSES | PANDAS_STATE_ONLY | frozenset({
    # dabl 0.2.6.2 and 0.3.2: BaseEstimator subclasses with no pickling hooks, __setattr__,
    # __getattr__ or properties (available_if descriptors only run on attribute access)
    ("dabl.preprocessing", "EasyPreprocessor"),
    ("dabl.models", "SimpleClassifier"),
    ("dabl.models", "SimpleRegressor"),
    SKLEARN_THRESHOLD_SCORER,
})
# Called only through REDUCE, each with its argument check in pickle_static._argument_check:
# * BlockManager(blocks, axes): libinternals.BlockManager.__reduce__ returns (type(self),
#   (self.blocks, self.axes)); __cinit__ stores the tuple and axes.copy() (pandas 1.4.4
#   internals.pyx:677-742, 3.1.0 internals.pyx:745-864). Accepted: a tuple of blocks made by
#   _unpickle_block and a list of two pandas Index objects.
# * _unpickle_block(values, placement, ndim): Block.__reduce__ returns (_unpickle_block,
#   (values, mgr_locs.indexer, ndim)); it calls new_block (1.4.4 internals.pyx:568, 3.1.0
#   internals.pyx:629, which also calls maybe_coerce_values and BlockPlacement). Accepted: a
#   numpy array, a slice or int, and ndim 1 or 2.
PANDAS_CALLS = frozenset({PANDAS_BLOCK_MANAGER, PANDAS_UNPICKLE_BLOCK})
# Old module paths of reviewed classes (0.9.0, static/upstream/historical_paths.json,
# generated by tools/gen_historical_paths.py from older releases): each is accepted under the
# same rule as the class it became. Policy classes resolve through upstream.state_only.
HISTORICAL_STATE_ONLY = _upstream.historical_by_form("state-only")
HISTORICAL_ZERO_ARG = _upstream.historical_by_form("zero-arg")
HISTORICAL_ENUM = _upstream.historical_by_form("enum")
HISTORICAL_GLOBALS = _upstream.historical_by_form("allowlist")
STATE_ONLY_CLASSES = STATE_ONLY_CLASSES | HISTORICAL_STATE_ONLY
ZERO_ARG_CLASSES = ZERO_ARG_CLASSES | HISTORICAL_ZERO_ARG
ENUM_CLASSES = ENUM_CLASSES | HISTORICAL_ENUM
PICKLE_GLOBALS = PICKLE_GLOBALS | HISTORICAL_GLOBALS
ARGUMENT_CHECKED = (STATE_ONLY_CLASSES | ENUM_CLASSES | ZERO_ARG_CLASSES | PANDAS_CALLS | SCORER_FUNCTIONS
                    | {PANDAS_NEW_INDEX, DEFAULTDICT})
PICKLE_GLOBALS = PICKLE_GLOBALS | ARGUMENT_CHECKED

# builtins.getattr is how pickle writes a bound method: getattr(obj, "name"). It is never
# on the allowlist; pickle_static._check_getattr judges every use (owner's rule, 2026-10-19):
# * MALICIOUS when the result is called, or the name is a dunder or a sink name;
# * CLEAN for getattr(<instance or class from the allowlist>, "<constant name without a
#   leading _>") whose result is never called while loading;
# * RISKY (not overridable) for anything else.
GETATTR = frozenset({("builtins", "getattr"), ("__builtin__", "getattr")})

# Extra globals a PyTorch checkpoint (data.pkl or a legacy stream) may import.
# Source: the globals torch.save emits for tensors, parameters and state dicts,
# as listed in torch's own weights-only unpickler. Unverified until milestone 6.
_TORCH_STORAGES = (
    "FloatStorage", "DoubleStorage", "HalfStorage", "BFloat16Storage", "LongStorage",
    "IntStorage", "ShortStorage", "CharStorage", "ByteStorage", "BoolStorage",
    "ComplexFloatStorage", "ComplexDoubleStorage",
)
_TORCH_DTYPES = (
    "float32", "float64", "float16", "bfloat16", "int64", "int32", "int16", "int8",
    "uint8", "bool", "complex64", "complex128",
)
TORCH_GLOBALS: frozenset[tuple[str, str]] = frozenset(
    [("torch", s) for s in _TORCH_STORAGES]
    + [("torch", d) for d in _TORCH_DTYPES]
    + [
        ("torch._utils", "_rebuild_tensor"),
        ("torch._utils", "_rebuild_tensor_v2"),
        ("torch._utils", "_rebuild_parameter"),
        ("torch._utils", "_rebuild_parameter_with_state"),
        ("torch.storage", "UntypedStorage"),
        ("torch", "Size"),
        ("torch", "device"),
        ("collections", "OrderedDict"),
        ("builtins", "set"),
        ("builtins", "tuple"),
        ("builtins", "list"),
        ("builtins", "dict"),
    ]
)

# Imports that are not merely unknown but known code-execution, process,
# filesystem or network sinks. Used to tell MALICIOUS from SUSPICIOUS; it is NOT
# an allowlist in reverse: anything outside the allowlist is suspicious anyway.
DANGEROUS_MODULES = frozenset({
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "builtins",
    "__builtin__", "importlib", "pty", "commands", "pickle", "_pickle", "runpy",
    "code", "codeop", "ctypes", "_posixsubprocess", "multiprocessing", "asyncio",
    "pydoc", "pdb", "bdb", "timeit", "cProfile", "profile", "trace", "webbrowser",
    "marshal", "pip", "ensurepip", "venv", "zipimport", "_pyrepl", "urllib",
    "http", "ftplib", "smtplib", "telnetlib", "requests", "antigravity", "tempfile",
    "io", "_io", "pathlib", "glob", "signal", "threading", "_thread",
})
# Library functions outside DANGEROUS_MODULES that run a string as code or a shell
# command: known sinks (MALICIOUS), like os.system (0.8.0; they were RISKY before).
EXEC_GADGETS = frozenset({
    ("numpy.testing._private.utils", "runstring"),  # exec() of a string
    ("_osx_support", "_read_output"),  # runs a shell command
    ("_osx_support", "_find_build_tool"),  # runs a shell command
})
# Built-ins a pickled class is rebuilt with (cloudpickle's
# _make_skeleton_class(type, ...), staticmethod, classmethod and property wrappers in the
# class dict) and dill's ``__builtin__.__main__``, which dill's find_class maps to the
# globals of the loading program. They build a class, wrap a function or hand over a
# namespace; they run no code of their own, so they are not known sinks (0.8.0; they were
# MALICIOUS as members of ``builtins``). Part of KNOWN_GADGETS: RISKY, never UNVERIFIABLE.
CLASS_BUILDERS = frozenset({(m, n) for m in ("builtins", "__builtin__")
                            for n in ("type", "staticmethod", "classmethod", "property", "__main__")})
# Globals outside the two sets above that public scanner bypasses use to run code or to
# call an argument (tests/corpus/build_corpus.py:bypass_payloads). EXEC_GADGETS are known
# sinks; the others do not change the verdict, they only keep the reason RISKY instead of
# UNVERIFIABLE, because the scanner does know what they do, so no override can accept them.
# pathlib's path classes (CPython 3.8-3.14 Lib/pathlib): PurePath.__reduce__ is (cls, parts)
# and constructing one only parses the strings, with no filesystem access; a Windows
# checkpoint holds WindowsPath objects (ultralytics train_args). Not known sinks (0.10.0,
# DECISIONS.md "pathlib path classes"): RISKY like CLASS_BUILDERS. Their methods
# (Path.write_text, Path.unlink, ...) as globals, or reached through getattr, stay sinks.
# Matched by the root package and the exact class name (is_path_class): CPython 3.13 defines
# the classes in pathlib._local, so a 3.13 pickle names that module; 3.8-3.12 and 3.14 name
# pathlib. Every pathlib submodule of 3.8-3.14 that has one of these names (pathlib._local,
# 3.14's pathlib.types) holds the same class.
PATH_CLASS_NAMES = frozenset({"PurePath", "PurePosixPath", "PureWindowsPath", "Path", "PosixPath", "WindowsPath"})
PATH_CLASSES = frozenset({("pathlib", n) for n in PATH_CLASS_NAMES})


def is_path_class(module: str, name: str) -> bool:
    """One of pathlib's path classes, under ``pathlib`` or any module inside it."""
    return module.split(".", 1)[0] == "pathlib" and name in PATH_CLASS_NAMES


KNOWN_GADGETS = frozenset({
    ("numpy.testing._private.utils", "runstring"),  # exec() of a string
    ("_osx_support", "_read_output"),  # runs a shell command
    ("_osx_support", "_find_build_tool"),  # runs a shell command
    ("functools", "partial"),  # calls its first argument
    ("functools", "reduce"),  # calls its first argument
    ("operator", "methodcaller"),  # calls a method by name
    ("operator", "attrgetter"),  # attribute access by name
}) | CLASS_BUILDERS | PATH_CLASSES


def is_known_gadget(module: str, name: str) -> bool:
    """In KNOWN_GADGETS, or a path class under a pathlib submodule (is_path_class)."""
    return (module, name) in KNOWN_GADGETS or is_path_class(module, name)

# dill (0.3.8 and 0.4.1, dill/_dill.py; evaluation/results/source-review-2-20261019.md).
# Helpers that import, eval, call an argument, read attributes by name, unmarshal or open
# files: known sinks, like os.system.
DILL_MODULES = frozenset({"dill._dill", "dill.dill"})  # dill's find_class maps dill.dill to dill._dill
DILL_SINKS = frozenset({
    "_import_module", "_eval_repr", "_getattr", "_get_attr", "_create_type", "_create_ftype",
    "_unmarshal", "_create_filehandle", "_create_capsule", "_create_namedtuple",
})
# _create_array(f, args, state, npdict) is f(*args).__setstate__(state): dill's numpy
# array. With f numpy's own _reconstruct it rebuilds an array and runs no code; with any
# other f it calls that argument (pickle_static._dill_code: RISKY; f's own import is
# judged like any other, so a sink there is MALICIOUS). It was a known sink before 0.8.0.
DILL_ARRAY = "_create_array"
ARRAY_RECONSTRUCTORS = frozenset({("numpy.core.multiarray", "_reconstruct"),
                                  ("numpy._core.multiarray", "_reconstruct")})
# Helpers a plain dill function or set is rebuilt with. _create_code/_create_function build
# code (judged by pickle_static._dill_code: RISKY, MALICIOUS with sink names); _load_type is
# a lookup in a fixed table; _create_cell and _setitems hold or copy data.
DILL_CODE = frozenset({"_create_code", "_create_function"})
DILL_DATA = frozenset({"_load_type", "_create_cell", "_setitems"})

# cloudpickle (3.1, cloudpickle/cloudpickle.py). A function is written as
# _make_function(_builtin_type("CodeType")(<fields>), globals, name, argdefs, closure) and
# a class as _make_skeleton_class(type, name, bases, ...) with _class_setstate: the same
# path as dill's functions (pickle_static._dill_code: RISKY, MALICIOUS with sink names;
# the code is emulated). _builtin_type(name) is getattr(types, name), reviewed for
# CLOUDPICKLE_TYPES; subimport(name) imports a module by name (judged by that name).
CLOUDPICKLE_MODULES = frozenset({"cloudpickle.cloudpickle", "cloudpickle.cloudpickle_fast"})
CLOUDPICKLE_CODE = frozenset({"_builtin_type", "_make_function", "_function_setstate",
                              "_make_skeleton_class", "_class_setstate", "_make_skeleton_enum",
                              "_enum_setstate"})
CLOUDPICKLE_DATA = frozenset({"_make_empty_cell", "_make_cell", "_make_dict_keys", "_make_dict_values",
                              "_make_dict_items", "_get_dataclass_field_type_sentinel",
                              "_make_typevar", "dynamic_subimport"})
CLOUDPICKLE_IMPORT = "subimport"
CLOUDPICKLE_TYPES = frozenset({"CodeType", "CellType", "FunctionType", "LambdaType", "MethodType",
                               "MappingProxyType", "ModuleType", "SimpleNamespace", "ClassType"})

DANGEROUS_SYMBOLS = frozenset({
    "system", "popen", "spawn", "spawnl", "spawnv", "exec", "execv", "execve",
    "execfile", "eval", "compile", "Popen", "call", "check_call", "check_output",
    "run", "getoutput", "getstatusoutput", "__import__", "load", "loads",
    "fromfile", "connect", "getattr", "setattr", "delattr", "open", "pipepager",
    "pipe_pager", "timeit", "runctx", "runcode", "run_path", "run_module",
    "import_module", "write_file", "write_text", "write_bytes", "urlopen",
    "FortranFile", "memmap", "tofile", "save", "savez", "savetxt",
    # loaders that deserialise another file or buffer (pandas.read_pickle reads a pickle,
    # read_hdf can; a nested load is a second, unanalysed pickle)
    "read_pickle", "read_hdf", "load_pickle", "unpickle", "load_model",
    # file-system and process changes re-exported under their own names by library modules
    # (sklearn.datasets._lfw.remove is os.remove, keras.src.utils.file_utils.rmtree is shutil's)
    "remove", "unlink", "rmtree", "rmdir", "removedirs", "copyfile", "copytree", "symlink",
    "chmod", "chown", "truncate", "kill", "killpg",
})

# Attributes Python or pickle look up on an instance or set through a slot state. A BUILD
# state that sets one turns a later BUILD (inst.__setstate__(state)), a copy or a class
# switch into a call of whatever value it stored; pickle itself never writes one.
BUILD_HOOK_KEYS = frozenset({
    "__setstate__", "__getstate__", "__reduce__", "__reduce_ex__", "__class__", "__dict__",
    "__new__", "__init__", "__setattr__", "__getattr__", "__getattribute__", "__delattr__",
})

# --- Keras ------------------------------------------------------------------

# Modules under which Keras serializes its own objects. Exact strings.
KERAS_MODULES = frozenset({
    "keras", "keras.layers", "keras.models", "keras.initializers", "keras.regularizers",
    "keras.constraints", "keras.activations", "keras.optimizers",
    "keras.optimizers.schedules", "keras.losses", "keras.metrics", "keras.src.models.functional",
    "keras.src.models.sequential", "keras.src.engine.functional",
    "keras.src.engine.sequential", "keras.src.models.model",
})

# Exact (module, class_name) pairs accepted outside KERAS_MODULES x KERAS_CLASSES. A pair
# is not a module grant: no other class from these modules is accepted.
KERAS_CLASS_PAIRS = frozenset({
    # Keras's own ConvNeXt layer; its config is init_values and projection_dim (numbers)
    ("keras.src.applications.convnext", "LayerScale"),
    # how Keras 3 records keras.ops calls in a functional graph: fixed elementwise maths,
    # no callable argument (added one by one, never keras.src.ops.*)
    ("keras.src.ops.numpy", "Add"),
    ("keras.src.ops.numpy", "Multiply"),
    ("keras.src.ops.numpy", "Subtract"),  # 2026-10-19 review: elementwise, no callable argument
    ("keras.src.ops.numpy", "TrueDivide"),  # 2026-10-19 review: elementwise, no callable argument
    # the tf-keras module of TFOpLambda; the layer itself passes only when its op is on
    # TF_OP_ALLOWED (keras_static)
    ("keras.src.layers.core.tf_op_layer", "TFOpLambda"),
})

# Built-in Keras classes that may appear in a model config. Exact class names.
KERAS_CLASSES = frozenset({
    # containers
    "Functional", "Sequential", "Model", "InputLayer",
    # Keras 3 functional graphs mark a layer input with {"class_name": "__keras_tensor__",
    # "config": {"shape", "dtype", "keras_history"}}; functional.py turns it into a
    # reference to another layer's output and imports nothing
    # (tests/fixtures/h5/k3_lambda_benign.h5).
    "__keras_tensor__",
    # core / dense
    "Dense", "EinsumDense", "Activation", "Embedding", "Masking", "Identity",
    # convolution
    "Conv1D", "Conv2D", "Conv3D", "Conv1DTranspose", "Conv2DTranspose", "Conv3DTranspose",
    "SeparableConv1D", "SeparableConv2D", "DepthwiseConv1D", "DepthwiseConv2D",
    # pooling
    "MaxPooling1D", "MaxPooling2D", "MaxPooling3D", "AveragePooling1D", "AveragePooling2D",
    "AveragePooling3D", "GlobalMaxPooling1D", "GlobalMaxPooling2D", "GlobalMaxPooling3D",
    "GlobalAveragePooling1D", "GlobalAveragePooling2D", "GlobalAveragePooling3D",
    # recurrent
    "LSTM", "GRU", "SimpleRNN", "Bidirectional", "LSTMCell", "GRUCell", "SimpleRNNCell",
    "RNN", "TimeDistributed", "ConvLSTM1D", "ConvLSTM2D", "ConvLSTM3D",
    # normalization / regularization
    "BatchNormalization", "LayerNormalization", "GroupNormalization", "UnitNormalization",
    "Dropout", "SpatialDropout1D", "SpatialDropout2D", "SpatialDropout3D",
    "GaussianDropout", "GaussianNoise", "AlphaDropout", "ActivityRegularization",
    # attention
    "Attention", "AdditiveAttention", "MultiHeadAttention", "GroupedQueryAttention",
    # reshaping
    "Reshape", "Flatten", "Permute", "RepeatVector", "Cropping1D", "Cropping2D",
    "Cropping3D", "UpSampling1D", "UpSampling2D", "UpSampling3D", "ZeroPadding1D",
    "ZeroPadding2D", "ZeroPadding3D",
    # merging
    "Add", "Subtract", "Multiply", "Average", "Maximum", "Minimum", "Concatenate", "Dot",
    # activations as layers
    "ReLU", "LeakyReLU", "PReLU", "ELU", "Softmax",
    # preprocessing that carries no code
    "Rescaling", "Normalization", "Resizing", "CenterCrop",
    # dtype policy, initializers, regularizers, constraints
    "DTypePolicy", "FloatDTypePolicy",
    "GlorotUniform", "GlorotNormal", "HeUniform", "HeNormal", "LecunUniform", "LecunNormal",
    "Zeros", "Ones", "Constant", "RandomUniform", "RandomNormal", "TruncatedNormal",
    "Orthogonal", "VarianceScaling",
    "L1", "L2", "L1L2", "OrthogonalRegularizer",
    "MaxNorm", "MinMaxNorm", "NonNeg", "UnitNorm",
    # optimizers, losses, metrics in compile_config
    "Adam", "AdamW", "SGD", "RMSprop", "Adagrad", "Adadelta", "Adamax", "Nadam", "Ftrl",
    "ExponentialDecay", "PiecewiseConstantDecay", "CosineDecay",
    "MeanSquaredError", "MeanAbsoluteError", "BinaryCrossentropy",
    "CategoricalCrossentropy", "SparseCategoricalCrossentropy", "Huber",
    "Accuracy", "BinaryAccuracy", "CategoricalAccuracy", "SparseCategoricalAccuracy",
    "MeanMetricWrapper", "Mean", "AUC", "Precision", "Recall",
    # 2026-10-19 review (evaluation/results/allowlist-review-20261019.md). Augmentation
    # layers: the config is numbers and fixed-choice strings (fill_mode, interpolation,
    # mode), never a callable; any nested object is still checked on its own.
    "RandomRotation", "RandomTranslation", "RandomZoom", "RandomContrast", "RandomFlip",
    "OrthogonalInitializer",  # Keras 3's registered name for Orthogonal (gain, seed)
    "CategoricalFocalCrossentropy",  # loss; alpha, gamma, from_logits, label_smoothing, axis
    "R2Score",  # metric; class_aggregation, num_regressors
    # 0.10.0 review (keras 3.0.5 and 3.12.0 src/metrics/accuracy_metrics.py): MeanMetricWrapper
    # subclasses with a fixed fn; get_config is name, dtype, k (and from_sorted_ids, a bool)
    "TopKCategoricalAccuracy", "SparseTopKCategoricalAccuracy",
})

# Keras serializes functions as {"class_name": "function", "config": "<name>",
# "module": "keras.activations"}. Only these exact (module, name) pairs are fine.
KERAS_FUNCTIONS = frozenset(
    ("keras.activations", n) for n in (
        "relu", "sigmoid", "softmax", "tanh", "linear", "elu", "selu", "gelu", "swish",
        "silu", "softplus", "softsign", "exponential", "hard_sigmoid", "leaky_relu",
        "relu6", "mish", "log_softmax",
    )
)

# Layers that carry executable Python (marshalled bytecode or a named callable).
# A TFOpLambda whose op is on TF_OP_ALLOWED is not a finding (keras_static).
KERAS_CODE_LAYERS = frozenset({"Lambda", "TFOpLambda", "SlicingOpLambda"})

# TensorFlow functions a TFOpLambda may name (function-level, exact).
TF_OP_ALLOWED = frozenset({
    "math.add", "math.subtract", "math.multiply", "math.divide", "math.truediv",
    "math.reduce_sum", "math.reduce_mean", "math.reduce_max", "math.reduce_min",
    "math.sqrt", "math.square", "math.exp", "math.log", "math.abs", "math.maximum",
    "math.minimum", "math.sigmoid", "math.tanh", "nn.relu", "nn.softmax", "nn.sigmoid",
    "reshape", "transpose", "concat", "stack", "expand_dims", "squeeze", "cast",
    "matmul", "linalg.matmul", "__operators__.add", "__operators__.getitem",
    "compat.v1.transpose", "clip_by_value", "where", "ones_like", "zeros_like",
})

# Sinks that must never appear in Lambda bytecode or TF op names.
TF_DANGEROUS = frozenset({
    "io", "gfile", "write_file", "read_file", "py_function", "numpy_function",
    "py_func", "load_op_library", "load_library", "system", "popen", "exec", "eval",
    "compile", "__import__", "open", "subprocess", "socket", "urlopen", "getattr",
    "Popen", "remove", "rmtree", "unlink", "rename", "spawn", "fork", "ctypes",
    "importlib", "import_module", "builtins", "globals", "locals", "__builtins__",
    "__subclasses__", "__globals__", "__code__", "marshal", "pickle", "environ",
    "getenv", "listdir", "walk", "makedirs", "mkdir", "chmod", "connect", "send",
    "requests", "urllib", "http", "os", "sys", "posix", "nt", "shutil", "pty",
})

# --- legacy Keras HDF5 (.h5) -------------------------------------------------
# tf.keras 2.x writes objects as {"class_name": ..., "config": ...} with no
# "module" key. Such an object is accepted only if its class_name is in this exact
# set: every Keras 3 class above, plus Keras 2 built-ins that Keras 3 renamed or
# dropped. Source: tf.keras 2.15 keras/layers, keras/initializers, keras/optimizers
# __init__ exports; "Custom>Adam" etc. are how tf.keras 2.11-2.15 registers its own
# optimizers (seen in tests/fixtures/h5/k2_sequential.h5). No prefix rule: the
# "Custom>" names are listed one by one. Unverified beyond the fixtures until the
# Hugging Face measurement (Part D).
_KERAS2_OPTIMIZERS = ("Adam", "AdamW", "SGD", "RMSprop", "Adagrad", "Adadelta", "Adamax", "Nadam", "Ftrl",
                      "Lion", "Adafactor")
KERAS2_CLASSES = KERAS_CLASSES | frozenset(
    {
        "Model", "Functional", "Sequential", "InputLayer", "Wrapper",
        "ThresholdedReLU", "LocallyConnected1D", "LocallyConnected2D", "CuDNNLSTM", "CuDNNGRU",
        "StackedRNNCells", "PeepholeLSTMCell", "SpatialDropout1D",
        "PolynomialDecay", "InverseTimeDecay", "CosineDecayRestarts",
        "RootMeanSquaredError", "MeanIoU", "MeanAbsolutePercentageError", "MeanSquaredLogarithmicError",
        "Hinge", "SquaredHinge", "CategoricalHinge", "LogCosh", "KLDivergence", "Poisson",
        "CosineSimilarity", "BinaryFocalCrossentropy",
        "TrueDivide",  # 2026-10-19 review: Keras 3 elementwise op saved to .h5 without a module
    }
    | {f"Custom>{name}" for name in _KERAS2_OPTIMIZERS}
)

# Activation names a layer's "activation" / "recurrent_activation" string may use
# (keras.activations functions in tf.keras 2.x and Keras 3). A name outside the set
# is a custom activation the loader would look up elsewhere.
KERAS_ACTIVATION_NAMES = frozenset(name for _, name in KERAS_FUNCTIONS) | frozenset({
    "hard_silu", "hard_swish", "celu", "glu", "sparsemax", "squareplus", "tanh_shrink",
    "threshold", "soft_shrink", "hard_shrink", "hard_tanh", "log_sigmoid", "sparse_plus",
})

# Loss and metric names a training_config may give as strings (and as a
# MeanMetricWrapper's "fn"): tf.keras 2.x keras.losses / keras.metrics functions
# and their aliases.
KERAS_LOSS_NAMES = frozenset({
    "mean_squared_error", "mse", "MSE", "mean_absolute_error", "mae", "MAE",
    "mean_absolute_percentage_error", "mape", "MAPE", "mean_squared_logarithmic_error", "msle", "MSLE",
    "squared_hinge", "hinge", "categorical_hinge", "log_cosh", "logcosh", "huber", "huber_loss",
    "categorical_crossentropy", "sparse_categorical_crossentropy", "binary_crossentropy",
    "binary_focal_crossentropy", "categorical_focal_crossentropy", "kl_divergence", "kld", "KLD",
    "kullback_leibler_divergence", "poisson", "cosine_similarity",
})
KERAS_METRIC_NAMES = KERAS_LOSS_NAMES | frozenset({
    "accuracy", "acc", "binary_accuracy", "categorical_accuracy", "sparse_categorical_accuracy",
    "top_k_categorical_accuracy", "sparse_top_k_categorical_accuracy", "crossentropy", "ce",
})
