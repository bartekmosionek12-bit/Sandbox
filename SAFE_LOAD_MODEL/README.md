# 🛡️ SafeLoadAI

**Zaawansowane środowisko izolacyjne chroniące potoki MLOps przed atakami typu Supply Chain w modelach AI.**
*(Projekt przygotowany w ramach konkursu HackYeah – Kategoria: DEFENCE. Twórca: Bartosz Mosionek)*

---

## 📖 Opis Produktu

SafeLoadAI to autorska, stworzona przeze mnie biblioteka Pythona klasy korporacyjnej, zaprojektowana w celu mitygacji krytycznych podatności występujących podczas ładowania formatów uczenia maszynowego (takich jak Pickle `.pkl` czy Keras `.keras`). Zjawisko ukrywania złośliwego kodu (Remote Code Execution) w plikach z wagami stało się obecnie jednym z najgroźniejszych wektorów ataków wymierzonych w inżynierów Data Science oraz infrastrukturę produkcyjną.

Zaprojektowałem to narzędzie jako bezinwazyjny zastępnik (*Drop-in Replacement*) dla standardowych, podatnych funkcji ładujących. 

Moje oprogramowanie automatyzuje trójwarstwowy system ochrony przed deserializacją modelu:
1. **Analiza Statyczna:** Skuteczne parsowanie instrukcji wirtualnej maszyny (opcode) i konfiguracji archiwum bez ewaluacji kodu w pamięci, co eliminuje zagrożenie wykonania typu "on-load".
2. **Dynamiczna Detonacja:** Automatyczne wdrożenie odciętego od sieci kontenera Docker. Narzędzie testuje potencjalny złośliwy ładunek w rygorystycznie kontrolowanym środowisku (zablokowany system plików, brak uprawnień administracyjnych), stosując przechwytywanie wywołań systemowych (Monkey-Patching). Uczciwa granica: zwykły Docker dzieli jądro z hostem, więc nie jest izolacją pełną — dlatego wspierany jest też `SANDBOX_RUNTIME=runsc` (gVisor).
3. **Zautomatyzowany Sędzia AI:** Integracja z modelem LLM (Claude Sonnet), który w sposób deterministyczny ocenia zebrane logi z piaskownicy pod kątem intencji ataku. Wdrożyłem autorski mechanizm zabezpieczający przed manipulacją ze strony wirusa (Prompt Injection) z użyciem znaczników kryptograficznych (nonce).

Biblioteka nie obiecuje pewności, bo żadne narzędzie tej klasy nie może jej dać. Daje trzy niezależne sygnały zamiast jednego i **odmawia wczytania modelu, gdy któregokolwiek z nich brakuje** — w szczególności gdy detonacja nie może się odbyć, bo nie ma działającego Dockera. Pusty log z warstwy, która nie wystartowała, wygląda identycznie jak log pliku nieszkodliwego, więc traktowanie go jako przesłanki czystości byłoby fałszywym dowodem niewinności.

---

## 🚀 Krok po kroku: Jak wdrożyć i skorzystać z narzędzia

Zadbałem o to, aby instalacja oraz wdrożenie narzędzia w dowolnym projekcie MLOps przebiegało intuicyjnie.

### Krok 1: Wymagania systemowe
Przed rozpoczęciem upewnij się, że Twoje środowisko posiada:
* **Python w wersji 3.10 lub wyższej.**
* **Działający Docker Daemon:** Wirtualizacja środowiska obronnego opiera się na technologii Docker. Upewnij się, że usługa działa w tle.
* Opcjonalnie: Biblioteka `keras` (wymagana wyłącznie, jeśli planujesz przetwarzać pliki w formacie `.keras`).

### Krok 2: Pobranie i instalacja
Pobierz kod do swojego środowiska, a następnie zainstaluj moją bibliotekę systemowo.
```bash
git clone <adres_repozytorium>
cd SAFE_LOAD_MODEL
pip install -e .
```
*(Plik `pyproject.toml` automatycznie zainstaluje niezbędne zależności, w tym pakiet `anthropic` do obsługi modułu AI).*

### Krok 3: Konfiguracja środowiska
Dla poprawnego działania Sędziego LLM, wymagane jest zadeklarowanie klucza API w środowisku operacyjnym. W terminalu wykonaj polecenie:
```bash
# Systemy Linux / macOS:
export ANTHROPIC_API_KEY="twój-klucz-api"

# Systemy Windows (PowerShell):
$env:ANTHROPIC_API_KEY="twój-klucz-api"
```

### Krok 4: Użycie biblioteki we własnym kodzie
Aby zabezpieczyć aplikację, wystarczy dokonać zamiany systemowej funkcji ładującej na wywołanie mojego API. Zmiana ogranicza się do dwóch linijek kodu.

*Zamiast używać niebezpiecznego podejścia:*
```python
import pickle
model = pickle.load(open('nieznany_model.pkl', 'rb')) 
```

*Użyj zabezpieczonej wersji:*
```python
from sandbox_rce import safe_load_model

# Biblioteka automatycznie zidentyfikuje format pliku,
# przeanalizuje go w tle i zwróci bezpieczny obiekt.
model = safe_load_model('nieznany_model.pkl') 
```

### Co się stanie, gdy nie ma Dockera

Biblioteka **nie wczyta modelu**. Zamiast tego rzuci `SecurityException` z powodem, na przykład
„Demon Dockera nie odpowiada". Analiza statyczna sama nie jest dowodem niewinności, więc nie
wystarcza do wpuszczenia pliku.

Jeśli świadomie akceptujesz to ryzyko, możesz pominąć warstwę dynamiczną jawnym parametrem — nigdy
nie dzieje się to domyślnie:

```python
model = safe_load_model('model.pkl', require_detonation=False)
```

Wynik jest wtedy oznaczony wprost jako potwierdzony wyłącznie analizą statyczną.

### Krok 5: Weryfikacja działania (Gotowe skrypty testowe)
W folderze głównym przygotowałem zestaw skryptów udowadniających skuteczność rozwiązania. Sprawdź, jak system reaguje na prawdziwe zagrożenia.

Aby wczytać **bezpieczny** plik:
```bash
python test_1_clean_pkl.py
python test_2_clean_keras.py
```
*(Spodziewany rezultat: Narzędzie zachowa się transparentnie i wyświetli krótki komunikat o pomyślnej weryfikacji pliku).*

Aby wczytać **złośliwy** plik z ładunkiem RCE:
```bash
python test_3_evil_pkl.py
python test_4_evil_keras.py
```
*(Spodziewany rezultat: Narzędzie błyskawicznie zainicjuje izolację Docker, przechwyci próbę ataku, a w konsoli zaprezentuje szczegółowy, profesjonalnie sformatowany Raport Bezpieczeństwa wygenerowany przez asystenta AI).*

---

### Podgląd w przeglądarce (opcjonalnie)

W katalogu `app/` leży dashboard Flask. Nie jest osobnym produktem — to widok
dowodowy tego samego silnika, który biblioteka wywołuje pod spodem. Wrzucasz
plik, a on pokazuje obok siebie wynik parsera, surowy log z kontenera i werdykt
sędziego.

```bash
pip install flask
PORT=5050 python -m app.server      # Linux / macOS
$env:PORT=5050; python -m app.server  # Windows PowerShell
```

Następnie otwórz `http://127.0.0.1:5050`.

---

## Wersja 0.2: co się zmieniło i jak tego używać

Pełny opis zmian z uzasadnieniem: dokumentacja PDF w materiałach projektu.
Krótko:

**Bramka odmawia wczytania w pięciu sytuacjach** (każda ma stały kod w
`SecurityException.code` i w `report["gate"]["code"]`):

| kod | kiedy |
|---|---|
| `blocked_verdict` | werdykt końcowy inny niż `safe`/`clean` |
| `no_detonation` | detonacja się nie odbyła (np. brak Dockera) |
| `detonation_timeout` | kontener przekroczył limit czasu — ładunek mógł czekać dłużej |
| `load_failed_in_sandbox` | w kontenerze samo wczytanie się nie powiodło |
| `changed_after_scan` | plik zmienił się między skanem a wczytaniem |

Trzy ostatnie powody wyłącza tylko jawne `require_detonation=False`.

**Sędzia LLM nie może obniżyć twardych przesłanek.** Jeśli detonacja
zarejestrowała wywołanie powłoki, proces albo próbę połączenia, werdykt jest
`malicious` niezależnie od tego, co napisał sędzia. Jeśli parser ocenił plik
jako `malicious` albo sędzia zgłosił próbę prompt injection, werdykt nie
spada poniżej `suspicious`. Bez klucza API log detonacji też się liczy.

**Skan i wczytanie dotyczą tej samej kopii pliku** (prywatny katalog
tymczasowy), więc podmiana pliku w trakcie skanu nic nie daje.

**Wiersz poleceń do CI:**

```bash
safeloadai scan models/ --report raport.json      # albo: python -m sandbox_rce scan ...
```

Kody wyjścia: `0` wszystko przeszło, `1` coś zablokowano, `2` błędne
wywołanie, `3` nie dało się potwierdzić czystości. Przykład dla GitHub
Actions: [`examples/github-actions.yml`](examples/github-actions.yml).

**Cache po skrócie pliku** (domyślnie wyłączony):
`safe_load_model(path, cache_dir="~/.cache/safeloadai")`, `--cache-dir`
albo zmienna `SAFELOADAI_CACHE_DIR`. Zapisywane są tylko pełne skany, a klucz
zawiera skrót pliku i odcisk silnika, więc zmiana kodu lub modelu sędziego
unieważnia wpis. Kto może pisać do katalogu cache, ten może wpisać plikowi
werdykt — katalog musi należeć tylko do użytkownika albo zadania CI.

**Obraz detonera przebudowuje się sam**, gdy zmieni się jego kod
(etykieta ze skrótem plików źródłowych). Obraz pickle zawiera teraz numpy
i scikit-learn, żeby prawdziwe modele dało się w nim wczytać — wersje
warto zrównać z projektem w `docker/requirements-pickle.txt`.

**Testy bez Dockera:** `pip install -e .[dev]`, potem `python -m pytest tests`.
Pomiar parsera na wygenerowanym korpusie: `python -m tools.eval_static`.

**Granice, które zostają:** zwykły Docker dzieli jądro z hostem (silniejsza
izolacja: `SANDBOX_RUNTIME=runsc`); po czystym werdykcie plik jest
wczytywany na maszynie klienta poza kontenerem, a kod z warstw Lambda
wykonuje się tam przy każdym wywołaniu modelu; detonacja to jedna
obserwacja, więc ładunek świadomy środowiska zostawi pusty log; skan `.keras`
trwa około minuty, bo startuje TensorFlow; nie ma ewaluacji na publicznym
korpusie złośliwych modeli.

---

## ⚖️ Oświadczenie o wykorzystaniu AI (HackYeah Rules)
Zgodnie z regulaminem hackathonu pragnę w pełni i transparentnie poinformować o wykorzystaniu AI. Cały ten projekt, włączając w to kod źródłowy biblioteki Pythona, architekturę izolacji w środowisku Docker, skrypty testowe oraz niniejszą dokumentację, **został w 100% zaprojektowany i napisany przeze mnie we współpracy z asystentem LLM (Claude)**. Wewnętrzna heurystyka produktu opiera się na API Anthropic (model Claude Sonnet). Jako wyłączny twórca całkowicie rozumiem działanie wygenerowanego kodu, jestem w stanie obronić mechanizmy jego wdrożenia i ponoszę pełną odpowiedzialność techniczną za przygotowane rozwiązanie.
