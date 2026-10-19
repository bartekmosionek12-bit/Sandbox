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
    # transformers' training arguments (training_args.bin): plain dataclasses. Rebuilt
    # from state, __post_init__ (which sets up devices and reads config files) never runs;
    # the fields are data, and an enum field is checked by ENUM_CLASSES.
    ("transformers.training_args", "TrainingArguments"),
    ("transformers.training_args_seq2seq", "Seq2SeqTrainingArguments"),
})
# Enum classes, accepted only as cls(value) with one str or int argument: a member lookup.
ENUM_CLASSES = frozenset({
    ("transformers.trainer_utils", "IntervalStrategy"),
    ("transformers.trainer_utils", "SchedulerType"),
    ("transformers.trainer_utils", "HubStrategy"),
    ("transformers.training_args", "OptimizerNames"),
    ("accelerate.utils.dataclasses", "DistributedType"),
})
# pandas.core.indexes.base._new_Index(cls, d) returns cls.__new__(cls, **d): it calls its
# first argument. Accepted only as pandas writes it, _new_Index(<an Index class>, {"data":
# ..., "name": ...}) (pandas 3.0.5 Index.__reduce__).
PANDAS_NEW_INDEX = ("pandas.core.indexes.base", "_new_Index")
PANDAS_INDEX_CLASSES = frozenset({("pandas.core.indexes.base", "Index")})
PANDAS_INDEX_KEYS = frozenset({"data", "name"})
# collections.defaultdict(factory): the factory is called later, on a missing key, never
# while loading. Accepted only with no factory or a builtin container or number type.
DEFAULTDICT = ("collections", "defaultdict")
DEFAULTDICT_FACTORIES = frozenset(
    (module, name) for module in ("builtins", "__builtin__")
    for name in ("list", "dict", "set", "frozenset", "tuple", "int", "float", "str", "bytes", "bool")
)
ARGUMENT_CHECKED = STATE_ONLY_CLASSES | ENUM_CLASSES | {PANDAS_NEW_INDEX, DEFAULTDICT}
PICKLE_GLOBALS = PICKLE_GLOBALS | ARGUMENT_CHECKED

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
# Globals outside the two sets above that public scanner bypasses use to run code or to
# call an argument (tests/corpus/build_corpus.py:bypass_payloads). They do not change the
# verdict; they only keep the reason RISKY instead of UNVERIFIABLE, because the scanner
# does know what they do, so no override can accept them.
KNOWN_GADGETS = frozenset({
    ("numpy.testing._private.utils", "runstring"),  # exec() of a string
    ("_osx_support", "_read_output"),  # runs a shell command
    ("_osx_support", "_find_build_tool"),  # runs a shell command
    ("functools", "partial"),  # calls its first argument
    ("functools", "reduce"),  # calls its first argument
    ("operator", "methodcaller"),  # calls a method by name
    ("operator", "attrgetter"),  # attribute access by name
})

DANGEROUS_SYMBOLS = frozenset({
    "system", "popen", "spawn", "spawnl", "spawnv", "exec", "execv", "execve",
    "execfile", "eval", "compile", "Popen", "call", "check_call", "check_output",
    "run", "getoutput", "getstatusoutput", "__import__", "load", "loads",
    "fromfile", "connect", "getattr", "setattr", "delattr", "open", "pipepager",
    "pipe_pager", "timeit", "runctx", "runcode", "run_path", "run_module",
    "import_module", "write_file", "write_text", "write_bytes", "urlopen",
    "FortranFile", "memmap", "tofile", "save", "savez", "savetxt",
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
        "RootMeanSquaredError", "MeanIoU", "TopKCategoricalAccuracy",
        "SparseTopKCategoricalAccuracy", "MeanAbsolutePercentageError", "MeanSquaredLogarithmicError",
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
