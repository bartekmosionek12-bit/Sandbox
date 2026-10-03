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
