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

## Docker na Windows — instalacja krok po kroku

Docker Desktop na Windows potrzebuje WSL2. To **nie** jest instalacja
Linuksa obok Windowsa: WSL2 to mała, ukryta maszyna wirtualna, w której
Docker trzyma kontenery. Nie zmienia dysku ani rozruchu, nie trzeba
instalować Ubuntu, a całość można odinstalować jak zwykły program.
Dla sandboksa to zaleta — payload działa w kontenerze wewnątrz tej
maszyny, a nie bezpośrednio na Windowsie.

W PowerShellu uruchomionym **jako administrator**:

```powershell
wsl --install --no-distribution
```

Jeśli polecenie zwraca „Zabronione” (HTTP 403 — GitHub ogranicza liczbę
zapytań z jednego adresu IP, częste w sieci współdzielonej), użyj zamiast
niego:

```powershell
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
winget install --id Microsoft.WSL -e
```

Potem:

1. Zrestartuj komputer.
2. Zainstaluj Docker Desktop (`winget install Docker.DockerDesktop` albo
   instalator ze strony Dockera) i uruchom go z menu Start.
3. Zaakceptuj licencję i poczekaj na status „Engine running”.
4. Sprawdź w zwykłym terminalu:

```powershell
docker run --rm hello-world
```

Na Windows zamiast `make ...` i `python3` używaj poleceń `python -m ...`
podanych niżej; obraz detonera buduje się sam przy pierwszej detonacji.

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

## Testy

```bash
make test        # 26 testów
```

Testy detonera uruchamiają własne fixture'y PoC jako podproces, więc po
przebiegu w `/tmp` pojawi się plik-znacznik `pwned` i `sandbox_poc_note.txt`.
To zamierzone: test pilnuje, że instrumentacja faktycznie przechwytuje
wykonanie. Pusty log jest gorszy niż brak detonacji, bo wygląda jak dowód
niewinności.

## Co jest świadomie poza zakresem v1

Te rzeczy są kierunkiem rozwoju, nie brakiem:

- **`.keras`** — ten sam pipeline, parser czytający `config.json` pod kątem
  Lambda layers i `custom_objects`. Kontrakty JSON są już pod to
  przygotowane: dashboard i sędzia nie znają formatu pliku.
- **Quorum kilku niezależnych LLM** zamiast jednego sędziego — redukuje
  ślepe punkty pojedynczego modelu, kosztem czasu integracji.
- **Izolacja klasy produkcyjnej** (gVisor / Firecracker) — zwykły kontener
  ma znane techniki ucieczki. Świadomy kompromis czasowy, nie przeoczenie.
- **Kontrolowany egress z logowaniem** zamiast pełnego odcięcia sieci —
  pozwala obserwować, dokąd malware próbuje się połączyć, a nie tylko
  blokować.
- **Data poisoning / backdoory w datasetach** — osobny problem badawczy
  (spectral signatures, activation clustering).

## Architektura

```
plik .pkl
   │
   ├─► parser.py      pickletools.genops, bez wykonywania  ──► schemas/parser.schema.json
   │
   ├─► sandbox.py ──► docker run --network=none --read-only
   │                      └─ detonate.py  prawdziwy pickle.load() ──► schemas/sandbox.schema.json
   │
   └─► judge.py       jedno wywołanie LLM, dane w bloku z nonce ──► schemas/judge.schema.json
                                   │
                              pipeline.py ──► app/server.py (dashboard)
```
