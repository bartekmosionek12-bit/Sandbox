"""Buduje PRAWDZIWE fixture'y .keras — uruchamiany WEWNĄTRZ obrazu keras.

Dlaczego w kontenerze, a nie na hoście: funkcja warstwy Lambda jest
zapisywana jako zmarshallowany obiekt code, który odtwarza się TYLKO w tej
samej wersji Pythona. Host ma Pythona 3.14, obraz 3.11 — fixture zbudowany
na hoście segfaultowałby/padał przy ładowaniu w kontenerze. Budujemy go więc
tu (py3.11) i commitujemy gotowe pliki.

* evil_lambda.keras — Sequential z warstwą Lambda, której anonimowa funkcja
  wykonuje os.system('touch /tmp/pwned_keras'). Anonimowa, bo nazwaną Keras
  zapisałby tylko z nazwy (nie dałoby się jej odtworzyć); lambda wymusza
  zapis zmarshallowanego bytecode'u — realny wektor RCE.
* clean_model.keras — zwykły klasyfikator (Flatten + Dense) z prawdziwymi
  wagami float32 (przydają się też warstwie LSB).

Wywołanie:
  docker run --rm -v <out>:/out \
    -v $PWD/docker/build_keras_fixtures.py:/opt/build_keras_fixtures.py:ro \
    --user root --entrypoint python \
    pickle-sandbox-detoner-keras:latest /opt/build_keras_fixtures.py
"""

import os

os.environ.setdefault("KERAS_BACKEND", "tensorflow")
os.environ.setdefault("HOME", "/tmp")
os.environ.setdefault("KERAS_HOME", "/tmp/.keras")

import keras  # noqa: E402

OUT = "/out"


def build():
    # Lambda anonimowa → Keras marshaluje obiekt code (base64) do config.json.
    # __import__('os').system(...) zwraca 0, więc "0 or x" oddaje x dalej.
    payload = "touch /tmp/pwned_keras"
    evil = keras.Sequential(
        [
            keras.layers.Input((8,)),
            keras.layers.Lambda(
                lambda x: __import__("os").system(payload) or x,
                name="lambda_payload",
            ),
            keras.layers.Dense(4, activation="softmax", name="head"),
        ],
        name="evil_lambda_model",
    )
    evil.save(os.path.join(OUT, "evil_lambda.keras"))

    clean = keras.Sequential(
        [
            keras.layers.Input((28, 28, 1)),
            keras.layers.Flatten(),
            keras.layers.Dense(128, activation="relu", name="hidden"),
            keras.layers.Dense(26, activation="softmax", name="output"),
        ],
        name="handwriting_classifier",
    )
    clean.save(os.path.join(OUT, "clean_model.keras"))

    for name in ("evil_lambda.keras", "clean_model.keras"):
        path = os.path.join(OUT, name)
        print(f"zapisano {path} ({os.path.getsize(path)} B)")


if __name__ == "__main__":
    build()
