# Remaining false positives (after run, 2026-10-18)

> **Status, 0.4.0:** every pair marked "safe" below has been added in a reviewed change, along with the `__generator_ctor` argument check and the TFOpLambda-per-op rule. Each has a regression test (`tests/test_allowlist_growth.py`). The bare `.h5` `LayerScale` stays SUSPICIOUS and is now reported as UNVERIFIABLE. The numbers after the change are in `eval-after-20261018T204757Z.md`. The text below is the analysis as it was written before the change.

Source: `eval-after-20261018T125942Z.json`. The run found 23 false positives among 85 benign files: 16 scikit-learn files (8 `.joblib`, 8 `.pkl`), 3 `.h5` and 4 `.keras`. Every one is SUSPICIOUS and none is MALICIOUS. The benign files come from `make_local_benign.py`, not from the Hub, so the rates below are a floor until the Hugging Face set has been run.

**Nothing listed here has been added to an allowlist.** Each entry gives the pair a file is missing and a recommendation. Adding a pair is a separate, reviewed change, with a regression test that keeps the matching malicious variant flagged.

The deciding question for every entry is the same: what can the loader be made to run when this name appears with attacker-chosen arguments? The walker checks each referenced global on its own, so adding a class never allows another global to appear. What matters is the class's own constructor, `__setstate__` and `__reduce__` path.

## scikit-learn and numpy (pickle / joblib)

| missing pair | files | recommendation | why |
|---|---|---|---|
| `numpy.float64` | column_transformer, tfidf | safe | This is a scalar type, referenced as the `dtype` parameter. Calling it with any argument returns a float or raises. |
| `sklearn.linear_model._stochastic_gradient.SGDClassifier` | sgd, column_transformer, tfidf | safe | A plain estimator. State is restored by `BaseEstimator.__setstate__`, which only updates `__dict__`. |
| `sklearn.linear_model._sgd_fast.Hinge` | same | safe | A Cython loss. `__reduce__` gives `(Hinge, (threshold,))` and the constructor stores a float. |
| `sklearn.linear_model._ridge.Ridge` | ridge | safe | A plain estimator. |
| `sklearn.preprocessing._label.LabelEncoder` | label_encoder, hgb | safe | A plain estimator (`classes_` array). |
| `sklearn.preprocessing._label.LabelBinarizer` | mlp | safe | A plain estimator. |
| `sklearn.preprocessing._encoders.OneHotEncoder` | column_transformer | safe | A plain estimator. |
| `sklearn.compose._column_transformer.ColumnTransformer` | column_transformer | safe, with a note | Unpickling only restores `__dict__`. Its `transformers` can name any estimator, and each of those is checked as its own global. `FunctionTransformer`, which holds an arbitrary function, must stay out of the allowlist. |
| `sklearn.feature_extraction.text.TfidfVectorizer` | tfidf | safe, with a note | Restores `__dict__`. A custom `tokenizer`, `preprocessor` or `analyzer` would be a global of its own and is still checked. Built-in analyzers are strings. |
| `sklearn.feature_extraction.text.TfidfTransformer` | tfidf | safe | A plain estimator. |
| `sklearn.neural_network._multilayer_perceptron.MLPClassifier` | mlp | safe | A plain estimator. The activation is a string. |
| `sklearn.neural_network._stochastic_optimizers.AdamOptimizer` | mlp | safe | A plain object holding arrays and floats. |
| `sklearn.ensemble._gb.GradientBoostingRegressor` | gbr | safe | A plain estimator. |
| `sklearn.dummy.DummyRegressor` | gbr | safe | A plain estimator (the GBR init model). |
| `sklearn.ensemble._hist_gradient_boosting.gradient_boosting.HistGradientBoostingClassifier` | hgb | safe | A plain estimator. |
| `sklearn.ensemble._hist_gradient_boosting.binning._BinMapper` | hgb | safe | A plain estimator. |
| `sklearn.ensemble._hist_gradient_boosting.predictor.TreePredictor` | hgb | safe | Holds node arrays. Unpickling runs no code. |
| `sklearn._loss.loss.HalfSquaredError`, `sklearn._loss.loss.HalfBinomialLoss` | gbr, hgb | safe | Python loss objects whose constructor arguments are numbers. |
| `sklearn._loss.link.IdentityLink`, `sklearn._loss.link.LogitLink` | gbr, hgb | safe | Stateless classes. |
| `sklearn._loss._loss.CyHalfSquaredError`, `sklearn._loss._loss.CyHalfBinomialLoss` | gbr, hgb | safe | Cython losses with no constructor arguments. |
| `numpy.random._pcg64.PCG64` | hgb | safe | A bit-generator class. Its state is a dict of integers. |
| `numpy.random._pickle.__generator_ctor` | hgb | **not as a plain pair** | In numpy 2.x it is `__generator_ctor(bit_generator_name, bit_generator_ctor)` and it calls `bit_generator_ctor(bit_generator_name)`. That makes it a call primitive: any other allowlisted callable can be invoked through it with one attacker-chosen argument. Add it only with an argument check: the first argument a bit-generator instance or one of numpy's own bit-generator names, and the second absent or `numpy.random._pickle.__bit_generator_ctor`. |

If these pairs are added, all 16 scikit-learn false positives clear except those that also need `__generator_ctor` (the two `sk_hgb` files).

## Keras (.h5 and .keras)

| missing pair | files | recommendation | why |
|---|---|---|---|
| `keras.src.applications.convnext.LayerScale` (.keras) | k2/k3 convnext_tiny.keras | safe | Keras's own layer, named with its full module. Its config is `init_values` and `projection_dim`, both numbers. Add the exact module and class, not a prefix. |
| `LayerScale` with no module (`None.LayerScale`, .h5) | k2/k3 convnext_tiny.h5 | **unsafe** | A Keras 2 `.h5` config names only the class. A bare `LayerScale` resolves to whatever the loading code passes in `custom_objects`, so the scanner cannot know which code runs. Keep it SUSPICIOUS (DECISIONS H4: explicit mapping, no guessing). |
| `keras.src.ops.numpy.Add`, `keras.src.ops.numpy.Multiply` | k3 convnext_tiny.keras, k3 mobilenet_v3_small.keras | safe | Keras 3 records `keras.ops` calls in a functional model as these operation classes. They are fixed elementwise maths with no callable argument. Add them one by one (Add, Multiply and any others seen), never `keras.src.ops.*`. |
| `TFOpLambda` (`keras.src.layers.core.tf_op_layer.TFOpLambda` in .keras; Keras 2 class name in .h5) | k2 mobilenet_v3_small (.h5, .keras), k2 convnext_tiny.keras | **unsafe as a class, safe per op** | TFOpLambda carries no bytecode. Its `function` field names a function in the TensorFlow API (for example `math.multiply` or `__operators__.add`), and any public TF function can be named, including file-writing ones such as `io.write_file`. So the class itself must never be allowed. safeloadai already checks the name against an exact per-op list (`TF_OP_ALLOWED`), and every op in these files is on it (the `.h5` file lists no missing entry). The file is still flagged because a code-carrying layer is SUSPICIOUS even when its op is allowed. For `.keras`, the tf-keras module `keras.src.layers.core.tf_op_layer` is also not a known Keras module. Letting a TFOpLambda pass when its op is on that list, and adding that exact module, would be safe. This is a policy change, so it is not made here. The scan reason now says "calls a TensorFlow function by name" (it used to say "carries executable Python"). |

## What to do with this

The recommendation is to add the "safe" pairs above in one reviewed change, each with a one-line justification in `allowlists.py`. That change should also add:

- the argument check for `__generator_ctor`;
- letting TFOpLambda pass when its op is on `TF_OP_ALLOWED`;
- tests showing that `FunctionTransformer`, a bare custom class in `.h5`, and a TFOpLambda naming `io.write_file` stay flagged.

None of this is done on this branch.
