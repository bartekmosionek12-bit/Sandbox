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

## Działa i jest sprawdzone
- parser `.pkl` i parser `.keras`, oba z testami
- 7 plików PoC (4 × `.pkl`, 3 × `.keras`) dający pełny kontrast
- sędzia LLM z ochroną przed injection (logika sprawdzona, bez żywego API)
- dashboard, kontrakty JSON, **36 testów**
- dokumentacja instalacji (README)

## W trakcie
- pierwsza realna detonacja `.pkl` w kontenerze

## Jeszcze nie zrobione
- **detonacja `.keras`** (priorytet 2)
- **detekcja tensor steganography** (priorytet 3)
- logowany egress i `strace` — po domknięciu bramki

---

# CZĘŚĆ 4: Jak zamierzam zrobić nowe rzeczy

## Detonator `.keras`

Osobny obraz kontenera z Kerasem, w którym wykonuje się prawdziwe
`load_model(safe_mode=False)`. Te same flagi izolacji co dla `.pkl`.

**Ryzyko i mój plan:** pełny TensorFlow to ~600 MB i długi build. Zanim
po to sięgnę, spróbuję **Keras 3 z backendem `numpy`** (`KERAS_BACKEND=numpy`),
który jest dużo lżejszy. Jeśli wystarczy do odtworzenia warstwy Lambda —
oszczędzamy kilkaset MB i sporo czasu budowania. Jeśli nie — wracam do TF
i mówię o tym wprost.

## Tensor steganography (LSB w wagach float32)

Dwa osobne kroki, zgodnie z tym, co napisałem w części 1:

**Walidator (statystyczny, poza kontenerem — nic nie uruchamia):**
- wyciąga najmłodsze bity mantysy z tablic `float32`
- liczy **entropię** i **test chi-kwadrat** rozkładu LSB; w normalnie
  wytrenowanym modelu LSB są praktycznie losowe
- szuka w wyciągniętym strumieniu **struktury**: drukowalnego ASCII,
  nagłówków (`PK`, ELF, `#!/bin/sh`), fraz w rodzaju `import os`
- raportuje, **w której warstwie** i jaki procent bitów odstaje

**Detonator (w kontenerze):** wyciąga ładunek i sprawdza, czy w pliku jest
**wyzwalacz**, który by go uruchomił.

**Werdykt:**
- sama anomalia LSB → **suspicious** (może być kompresja albo kwantyzacja)
- anomalia LSB **+ wyzwalacz** → **malicious** (pełny łańcuch)

Uczciwie: ładunek zaszyfrowany lub skompresowany wygląda jak szum i będzie
**trudny do odróżnienia** od czystego modelu. Detektor złapie payloady
jawnym tekstem i wyraźne anomalie statystyczne, a nie wszystko. Powiem to
wprost, zamiast obiecywać stuprocentową skuteczność.

---

# Czego od Ciebie potrzebuję

1. **Sprawdź część 1** — czy dobrze zrozumiałem polecenia, zwłaszcza
   akapit o LSB.
2. **Klucz `ANTHROPIC_API_KEY`**, gdy dojdziemy do testowania sędziego na
   żywo.
3. **Decyzja**, gdyby zabrakło czasu: czy wolisz dopracowane `.pkl` +
   `.keras`, czy dołożone stego kosztem szlifu. Moja rekomendacja: dwa
   formaty zrobione porządnie biją trzy zrobione po łebkach, bo Design
   waży w ocenie 20%, a Completeness 10%.
