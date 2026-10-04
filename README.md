# SafeLoadAI

Produkt leży w katalogu [`SAFE_LOAD_MODEL/`](SAFE_LOAD_MODEL/) — biblioteka Pythona,
która wczytuje modele ML (`.pkl`, `.keras`) dopiero po przejściu trzech warstw
kontroli: parsera statycznego, detonacji w izolowanym kontenerze Dockera i oceny
sędziego LLM.

Instrukcja instalacji i użycia: [`SAFE_LOAD_MODEL/README.md`](SAFE_LOAD_MODEL/README.md).

W katalogu biblioteki leży też `app/` — dashboard Flask, który jest widokiem
dowodowym tego samego silnika (to z niego pochodzą zrzuty ekranu w materiałach).
Produktem jest biblioteka; dashboard służy do oglądania jej wyniku.

Wcześniejsza, równoległa kopia rdzenia oraz dokumentacja PDF i testy pytest
zostały usunięte z drzewa na rzecz biblioteki. Pliki pozostają w historii gita,
w commicie `712016c` i wcześniejszych.
