# Pickle Sandbox — detekcja RCE w plikach modeli ML (.pkl)

Narzędzie obronne (HackYeah, kategoria Defence). Pokazuje, że plik modelu
dystrybuowany jako pickle może wykonać dowolny kod przy `pickle.load()` —
i wykrywa to **trzema niezależnymi warstwami**:

1. **Parser statyczny** — `pickletools.dis()`, flagowanie opcode'ów `GLOBAL`
   i `REDUCE` oraz niebezpiecznych importów (`os`, `subprocess`, `sys`,
   `eval`, `exec`, `builtins`, `posix`).
2. **Sandbox detonacyjny** — prawdziwe `pickle.load()` w kontenerze Docker
   z `--network=none`; monkey-patch loguje każdą próbę wykonania polecenia,
   zapisu pliku i połączenia sieciowego.
3. **Sędzia LLM** — jedno wywołanie Claude Sonnet 4.5, które na podstawie
   wyniku parsera i logu z detonacji wydaje werdykt (safe / suspicious /
   malicious) z uzasadnieniem. Dane wejściowe są odseparowane od instrukcji
   (zabezpieczenie przed prompt injection z logów).

Wszystkie trzy warstwy komunikują się przez **kontrakty JSON** w `schemas/`,
więc dashboard i sędzia nie znają formatu pliku — dodanie `.keras` nie wymaga
przepisywania pipeline'u.

## Wymagania

- Python 3.11+
- Docker (do warstwy detonacyjnej) — bez niego pipeline działa dalej, ale
  sandbox zwraca `detonated: false` z wyraźnym powodem, bez udawania detonacji.
- `ANTHROPIC_API_KEY` w zmiennej środowiskowej (do sędziego) — bez klucza
  dashboard pokazuje parser + log bez werdyktu.

```bash
pip install -r requirements.txt
```

## Uruchomienie dashboardu

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # opcjonalne
python -m app.server
# otwórz http://127.0.0.1:5000
```

## Budowa plików PoC do demo

```bash
python -m poc.build_poc        # tworzy pliki w poc/samples/
```

Pliki PoC są **nieszkodliwe ale widoczne w logu**: `touch /tmp/pwned`, zapis
pliku tekstowego, próba połączenia sieciowego (zablokowana przez
`--network=none`). Jeden plik jest czysty, dla kontrastu.

## CLI (pełny pipeline bez dashboardu)

```bash
python -m sandbox_rce.pipeline poc/samples/evil_os_system.pkl
```

## Bezpieczeństwo

Detonacja uruchamia **nieufny kod**. Zawsze w kontenerze z `--network=none`.
Nie uruchamiaj `sandbox_rce.detonate` bezpośrednio na hoście na nieznanym
pliku — to detoner, który ma wykonać payload.
