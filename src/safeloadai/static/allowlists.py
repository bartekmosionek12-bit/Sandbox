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
    ]
)

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

# Built-in Keras classes that may appear in a model config. Exact class names.
KERAS_CLASSES = frozenset({
    # containers
    "Functional", "Sequential", "Model", "InputLayer",
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
