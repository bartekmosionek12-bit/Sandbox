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

Całość da się cofnąć: `wsl --uninstall` albo odznaczenie funkcji
w `optionalfeatures.exe`.

## Docker na Linux i macOS

Linux:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER   # wyloguj sie i zaloguj ponownie
```

macOS: Docker Desktop ze strony docker.com, uruchom i poczekaj na
„Engine running".

Sprawdzenie na obu: `docker run --rm hello-world`.

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

## Weryfikacja detonacji w Dockerze — krok po kroku

To jest procedura domykająca bramkę projektu: dowód, że payload wykonuje się
**w kontenerze**, a nie na Twoim komputerze. Wykonaj kroki po kolei,
w PowerShellu, w katalogu repo.

**1. Sprawdź, że silnik Dockera odpowiada.**

```powershell
docker info --format "{{.ServerVersion}}"
```

Ma wypisać numer wersji. Jeśli pisze cokolwiek o `docker API` albo `daemon`,
uruchom Docker Desktop i poczekaj, aż pokaże „Engine running".

**2. Pobierz aktualny kod.**

```powershell
git pull origin claude/pkl-rce-sandbox-pcdsri
```

**3. Wygeneruj pliki PoC.**

```powershell
python -m poc.build_poc
```

**4. Zbuduj obraz detonera.** Pierwszy raz trwa chwilę, bo ściąga
`python:3.11-slim`.

```powershell
docker build -t pickle-sandbox-detoner:latest -f docker/Dockerfile .
```

**5. Zdetonuj plik złośliwy.**

```powershell
python -m sandbox_rce.sandbox poc\samples\evil_os_system.pkl
```

Poprawny wynik ma te pola:

```json
"detonated": true,
"detonation_backend": "docker",
"load_succeeded": true,
"events": [
  { "type": "other",     "detail": "import posix" },
  { "type": "os_system", "detail": "touch /tmp/pwned" }
]
```

**6. Zdetonuj plik czysty, dla kontrastu.**

```powershell
python -m sandbox_rce.sandbox poc\samples\clean_model.pkl
```

Tu ma być `"detonated": true` i `"events": []`. Zero zdarzeń przy
poprawnym załadowaniu to jest dowód, że instrumentacja nie zmyśla.

**7. Sprawdź, że izolacja faktycznie trzymała.** Payload robił
`touch /tmp/pwned`. Jeśli kontener zadziałał, ten plik powstał w kontenerze
i zniknął razem z nim, a na Twoim komputerze go NIE MA:

```powershell
Test-Path C:\tmp\pwned
wsl -- test -f /tmp/pwned ; if ($LASTEXITCODE -eq 0) { "UWAGA: plik jest w WSL" } else { "ok, brak w WSL" }
```

Oba mają wyjść negatywnie. To jest właściwy koniec weryfikacji: payload się
wykonał, log to pokazał, a poza kontenerem nie zostało nic.

**8. Zdetonuj pozostałe dwa pliki**, żeby zobaczyć cały kontrast:

```powershell
python -m sandbox_rce.sandbox poc\samples\evil_file_write.pkl
python -m sandbox_rce.sandbox poc\samples\evil_network_beacon.pkl
```

Beacon ma w logu `"blocked": true` przy próbie połączenia. Fixture celuje
w nazwę w domenie `.invalid`, która z definicji nie istnieje, więc nawet bez
kontenera nic nigdzie nie wychodzi — a w kontenerze z `--network=none`
blokuje się dwukrotnie.

**9. Na koniec dashboard.**

```powershell
python -m app.server
```

Wgraj `evil_os_system.pkl` (czerwony banner, zdarzenia w panelu detonacji),
potem `clean_model.pkl` (zielony, zero zdarzeń).

Jeśli panel pisze, że detonacja się nie odbyła, to znaczy, że Docker nie
działa. Narzędzie **nigdy nie podstawia symulowanego logu** — brak
detonacji jest zawsze powiedziany wprost.

## Typowe problemy

| Objaw | Przyczyna | Co zrobić |
|---|---|---|
| `wsl --install` → „Zabronione" | HTTP 403 z `api.github.com`, limit zapytań z Twojego IP | Hotspot z telefonu (inny IP) albo `winget install --id Microsoft.WSL -e` |
| „failed to connect to the docker API" | Silnik nie wstał | Uruchom Docker Desktop i poczekaj na „Engine running" |
| Docker Desktop nie startuje na Windows 11 Home | Brak WSL2 (Home nie ma Hyper-V) | Wykonaj kroki z sekcji o Windows i zrestartuj komputer |
| Dashboard pisze o braku detonacji | Docker niewidoczny dla aplikacji | `docker run --rm hello-world` w tym samym terminalu, z którego startujesz dashboard |
| Brak werdyktu LLM | Brak `ANTHROPIC_API_KEY` | Ustaw klucz; bez niego parser i log działają normalnie |

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
