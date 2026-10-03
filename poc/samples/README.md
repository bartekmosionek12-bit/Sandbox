# Pliki PoC

Fixture'y testowe dla detektora. Pliki `evil_*.pkl` **wykonują kod przy
`pickle.load()`** — otwieraj je wyłącznie w sandboksie (`--network=none`).

| plik | mechanizm | widoczny efekt |
|---|---|---|
| `evil_os_system.pkl` | `__reduce__` → `os.system` | `touch /tmp/pwned` |
| `evil_file_write.pkl` | `__reduce__` → `os.system` | zapis `/tmp/sandbox_poc_note.txt` |
| `evil_network_beacon.pkl` | `__reduce__` → `socket.create_connection` | próba wyjścia na sieć (blokowana) |
| `clean_model.pkl` | zwykły dict, same typy wbudowane | brak — zielony werdykt |

Regeneracja: `python -m poc.build_poc`

## Pliki .keras

| plik | mechanizm | wykrywane jako |
|---|---|---|
| `evil_lambda.keras` | warstwa Lambda ze zserializowanym bytecode'em (`touch /tmp/pwned_keras`) | malicious |
| `evil_custom_object.keras` | `registered_name` + moduł spoza Kerasa | suspicious |
| `clean_model.keras` | zwykły Sequential, same warstwy Kerasa | clean |

Regeneracja: `python -m poc.build_poc_keras`

Detonacja `.keras` nie jest jeszcze zaimplementowana (wymaga obrazu
z TensorFlow/Keras), więc dla tego formatu pipeline robi analizę statyczną
i werdykt LLM, mówiąc wprost, że dowodu dynamicznego brak.
