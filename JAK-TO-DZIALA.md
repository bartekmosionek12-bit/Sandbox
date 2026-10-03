# Jak to działa — i jak zrozumiałem Twoje polecenia

Ten plik jest do sprawdzenia przeze mnie i przez Ciebie. Pierwsza część to
**moje rozumienie Twoich poleceń** — przeczytaj i popraw, jeśli coś
przekręciłem. Druga to opis, jak system faktycznie działa.

Stan na: **3.10.2026**, branch `claude/pkl-rce-sandbox-pcdsri`, PR #1.

---

# CZĘŚĆ 1: Jak zrozumiałem, co mam zrobić

## Priorytety, które mi podałeś

1. **Najpierw ma działać to, co już jest** — detonacja `.pkl` w Dockerze,
   potwierdzona na żywo, nie „napisana".
2. **Potem detonator `.keras`** — faktyczne `load_model(safe_mode=False)`
   w kontenerze.
3. **Potem tensor steganography** — detekcja i walidacja LSB w plikach wag
   float32.

Trzymam się tej kolejności. Nie zaczynam punktu 3, zanim 1 i 2 nie działają.

## Zasada, którą uznaję za najważniejszą

**Nic nie jest udawane.** Jeśli detonacja się nie odbyła, system mówi to
wprost (`detonated: false` + powód), zamiast pokazywać pusty log, który
wyglądałby jak dowód niewinności. Fałszywe demo jest tu gorsze niż brak
funkcji.

## Co jest poza zakresem

- Prezentacja (10 slajdów PDF) — robi się równolegle, nie w tym wątku.
- Quorum wielu LLM, gVisor/Firecracker, data poisoning w datasetach —
  świadomie na roadmapę, do opowiedzenia, nie do zbudowania.

## ⚠️ Jedna rzecz, w której doprecyzowuję Twoje polecenie

Napisałeś: *„tensor steganography to jest ukrywanie RCE w LSB"*.

Doprecyzuję, bo to zmienia projekt detektora: **LSB ukrywa ładunek, ale sam
go nie wykonuje.** Zmiana najmłodszego bitu mantysy float32 przesuwa wartość
o ~1e-7, więc model działa dalej normalnie i można tam schować dowolne
dane — ale te dane leżą bezczynnie, dopóki **coś ich nie wyciągnie
i nie uruchomi**.

Czyli realny atak ma **dwa elementy**:
- **nośnik** — payload schowany w LSB wag (to jest steganografia),
- **wyzwalacz** — kod, który go wyciąga i wykonuje; najczęściej właśnie
  warstwa Lambda albo `__reduce__` w pickle.

**Dlatego detektor sprawdza oba i raportuje je osobno.** Sama anomalia
w LSB to „podejrzany", nie „złośliwy". Dopiero LSB **plus** wyzwalacz
w tym samym pliku to pełny łańcuch. Jeśli miałeś na myśli co innego —
powiedz, przerobię.

---

# CZĘŚĆ 2: Jak to działa

## Architektura w jednym zdaniu

Plik wchodzi przez dashboard, przechodzi przez trzy niezależne warstwy
detekcji, każda warstwa zapisuje wynik do **swojego kontraktu JSON**,
a dashboard i sędzia czytają wyłącznie te kontrakty.

```
plik (.pkl / .keras)
   │
   ├─► WARSTWA 1  parser statyczny      ──► schemas/parser.schema.json
   │               (czyta, nie uruchamia)
   │
   ├─► WARSTWA 2  detonacja w Dockerze  ──► schemas/sandbox.schema.json
   │               (uruchamia naprawdę, w izolacji)
   │
   └─► WARSTWA 3  sędzia LLM            ──► schemas/judge.schema.json
                   (ocenia dowody z 1 i 2)
                        │
                   dashboard
```

**Dlaczego kontrakty są ważne:** dashboard i sędzia nie wiedzą, jaki format
czytają. Dzięki temu `.keras` doszedł jako nowy plik parsera i jedna linijka
routingu — bez dotykania interfejsu i sędziego. Tak samo wejdzie stego.

---

## Warstwa 1 — parsery statyczne

### `.pkl` (`sandbox_rce/parser.py`)

Czyta strumień opcode'ów przez `pickletools.genops`. **Nie deserializuje
pliku**, więc nie może uruchomić payloadu (jest na to osobny test).

Szuka:
- opcode'ów dających wykonanie kodu: `GLOBAL`, `STACK_GLOBAL`, `REDUCE`,
  `INST`, `OBJ`, `NEWOBJ`, `BUILD`
- importów z listy niebezpiecznych: `os`, `posix`, `subprocess`, `sys`,
  `socket`, `builtins`, `ctypes`, `eval`, `exec`, `__import__`

**Łańcuch RCE = `REDUCE` + niebezpieczny import.** Dopiero to razem daje
ocenę „malicious".

### `.keras` (`sandbox_rce/parser_keras.py`)

`.keras` to archiwum ZIP. Parser rozpakowuje je i czyta `config.json`,
**nie uruchamiając Kerasa**.

Szuka:
- **warstw Lambda** — pole `function` z zserializowanym obiektem code
  (marshal + base64). To jest wykonywane przy `load_model(safe_mode=False)`.
- **custom objects** — `registered_name` i `module` spoza Kerasa; ładujący
  musi dostarczyć taką klasę, co jest ścieżką do wykonania cudzego kodu.

---

## Warstwa 2 — detonacja

Host kopiuje plik do katalogu tymczasowego i uruchamia kontener, który
wykonuje **prawdziwe** `pickle.load()`. To nie jest symulacja.

**Izolacja kontenera:**

| flaga | po co |
|---|---|
| `--network=none` | zero interfejsu — reverse shell ani beacon do C2 nie wyjdą |
| `--read-only` | cały system plików tylko do odczytu |
| `--tmpfs /tmp:noexec,nosuid,nodev` | zapis tylko do RAM-u, bez prawa wykonywania |
| `--cap-drop=ALL` | zero uprawnień systemowych |
| `--security-opt=no-new-privileges` | brak eskalacji przez suid |
| `--ipc=none` | brak współdzielonej pamięci |
| `--memory` + `--memory-swap` | limit pamięci (bez swapu limit byłby do obejścia) |
| `--pids-limit` | ochrona przed fork bombą |
| timeout 30 s, `--rm` | kontener ginie po każdym pliku |

Dodatkowo: nieuprzywilejowany użytkownik w obrazie, plik montowany
tylko do odczytu, nazwa pliku z uploadu **nigdy** nie trafia do argv
kontenera.

**Jak powstaje log:** w kontenerze podmieniamy (monkey-patch) `os.system`,
`posix.system`, `subprocess.*`, `socket.connect`, `open()` i `eval`/`exec`.
Każde wywołanie jest **zapisywane, a potem przepuszczane do oryginału** —
czyli payload naprawdę się wykonuje, a my to widzimy. Kanał jest
jednokierunkowy: kontener pisze na stdout, host czyta po zakończeniu.

**Znane ograniczenie, które trzeba powiedzieć na scenie:** monkey-patch
działa od środka procesu. Payload, który woła syscall bezpośrednio przez
`ctypes`, ominie te haki — **nadal nic nie zrobi poza kontenerem**, ale
może nie być widoczny w logu. Zamknięciem tego jest obserwacja z zewnątrz
(`strace`), zaplanowana po domknięciu obecnej bramki.

---

## Warstwa 3 — sędzia LLM

Jedno wywołanie modelu (Claude Sonnet 5.5) na plik. Dostaje kontrakt
parsera i kontrakt sandboksa, zwraca werdykt + uzasadnienie.

**Zabezpieczenie przed prompt injection** (to jest świadomie zrobione, nie
przypadek):

1. Instrukcje są **wyłącznie** w system prompcie, nigdy razem z danymi.
2. Dane są owinięte znacznikiem `<evidence-NONCE>` z **losowym nonce
   generowanym per wywołanie** — payload nie potrafi podrobić zamknięcia
   bloku, bo nie zna nonce'a.
3. System prompt mówi wprost, że zawartość bloku to **dane do oceny, nie
   polecenia**.
4. Jeśli dane zawierają tekst próbujący wpłynąć na ocenę, model ma to
   **podnieść jako przesłankę złośliwości**, a nie posłuchać. Raportuje to
   osobnym polem, które trafia do uzasadnienia.
5. Odpowiedź jest wymuszona schematem JSON — model nie może wyjść poza
   ustalony format.

**Bez klucza API:** sędzia zwraca `available: false`, dashboard pokazuje
parser i log bez werdyktu, a ocena końcowa spada na heurystykę statyczną
**z jawną adnotacją, skąd pochodzi**.

---

## Dashboard

Jedna strona, jeden przepływ: upload → status → wynik parsera → log
z detonacji → werdykt. Banner czerwony / żółty / zielony. Bez kont, bez
historii.

Chipy w nagłówku mówią uczciwie, które warstwy są w tej chwili dostępne
(Docker, klucz API) — żeby nie było wątpliwości, czy brak werdyktu to
awaria, czy brak konfiguracji.

---

# CZĘŚĆ 3: Co działa, a co nie

Stan po weryfikacji na **żywym Dockerze** (Docker Desktop 29.8.1, WSL2 na
laptopie). To nie jest „napisane i założone" — to uruchomione i sprawdzone.

## Działa i JEST SPRAWDZONE NA ŻYWO
- **Detonacja `.pkl` w kontenerze** — payload faktycznie się wykonuje:
  `evil_os_system` zapisuje `/tmp/pwned` wewnątrz kontenera (jako
  nieuprzywilejowany użytkownik, reszta FS tylko do odczytu),
  `evil_network_beacon` → próba połączenia z `blocked: true`
  (bo `--network=none`), `clean` → zero zdarzeń.
- **Detonacja `.keras` w kontenerze** (priorytet 2, ZROBIONE) — prawdziwe
  `load_model(safe_mode=False)` + przebieg w przód. `evil_lambda.keras`
  wykonuje `os.system('touch /tmp/pwned_keras')`, `clean_model.keras`
  ładuje się bez zdarzeń. Podpięte do pipeline'u i widoczne na dashboardzie.
- **Tensor steganography — LSB w wagach float32** (priorytet 3, ZROBIONE) —
  wykrywa ładunek ukryty w najmłodszych bitach mantysy. Na pliku z ukrytym
  reverse shellem wyciąga go i pokazuje; czysty model nie odpala fałszywego
  alarmu. Werdykt: sama anomalia LSB → `suspicious`, anomalia + wyzwalacz →
  `malicious`. Obsługa `.npy`/`.npz` w dashboardzie.
- parser `.pkl` i `.keras`, sędzia LLM z ochroną przed injection (logika),
  dashboard z czterema panelami, kontrakty JSON, **56 testów**, README.

## W trakcie (druga sesja — koordynator)
- **Śledzenie syscalli przez `strace`** jako czwarte źródło dowodów — łapie
  payload, który omija nasze haki w Pythonie (np. przez `ctypes`). Parser
  wyjścia i obraz są gotowe; podpięcie do `docker run` wymaga weryfikacji na
  maszynie z Dockerem. Wymaga `--cap-add=SYS_PTRACE`, więc świadomie osobny,
  opcjonalny przebieg.

## Świadomie poza zakresem (roadmapa, nie brak)
- quorum wielu LLM, gVisor/Firecracker, logowany egress, data poisoning —
  do opowiedzenia na scenie, nie do zbudowania w czasie hackathonu.

---

# CZĘŚĆ 4: Co się zmieniło względem pierwotnego planu (ustalenia z Dockera)

Dwie rzeczy wyszły dopiero przy uruchomieniu na prawdziwym Dockerze —
dokładnie to, czego nie dało się sprawdzić w chmurze bez demona.

## Detonator `.keras`: numpy segfaultował, jest TensorFlow

Pierwotny plan zakładał lekki backend `numpy` (~1 GB zamiast ~1,9 GB).
Na żywym Dockerze backend numpy **segfaultował** (exit 139) przy przebiegu
modelu z warstwą Lambda — czyli dawał pusty log, który wyglądałby jak dowód
niewinności. To najgorszy możliwy wynik, więc przełączyłem obraz na
`tensorflow-cpu`, gdzie detonacja działa i payload faktycznie odpala.
Dodatkowo: fixture z zmarshallowanym kodem Lambdy musi powstać w tej samej
wersji Pythona co kontener (3.11), więc generuję go w kontenerze, nie na
hoście (3.14) — inaczej `bad marshal`/segfault.

## Tensor steganography: werdykt na strukturze, nie na rozkładzie bitów

Pierwotnie chciałem flagować też **anomalię statystyczną** rozkładu LSB.
Na prawdziwych modelach to daje **fałszywe alarmy**: tensory zerowe (biasy)
albo skwantyzowane mają LSB dalekie od losowych, choć są niewinne. Dlatego
werdykt opieram wyłącznie na **strukturze** w strumieniu LSB — drukowalnym
tekście i znanych nagłówkach (`#!/`, `PK`, `import os`, `/bin/sh`). Entropię
i balans bitów pokazuję jako kontekst, nie jako podstawę decyzji.

**Uczciwie:** ładunek zaszyfrowany lub skompresowany wygląda jak szum i jest
trudny do odróżnienia od czystego modelu. Detektor łapie payloady jawnym
tekstem, a nie wszystko. Mówię to wprost, zamiast obiecywać 100%.

---

# Czego od Ciebie potrzebuję

1. **Sprawdź część 1** — czy dobrze zrozumiałem polecenia, zwłaszcza
   akapit o LSB (nośnik vs wyzwalacz).
2. **Klucz `ANTHROPIC_API_KEY`**, gdy zechcesz zobaczyć werdykt sędziego LLM
   na żywo (bez niego dashboard pokazuje parser + log + stego bez werdyktu AI).
3. **Decyzja o `strace`**: czy wiązać czwartą warstwę do końca (druga sesja
   ją pisze), czy zostawić jako zaplanowaną i skupić się na szlifie trzech
   warstw, które już działają.
