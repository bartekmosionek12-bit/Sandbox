# Safe Tensor Sandbox

Produkt leży w katalogu [`SAFE_LOAD_MODEL/`](SAFE_LOAD_MODEL/) — biblioteka Pythona,
która wczytuje modele ML (`.pkl`, `.keras`) dopiero po przejściu trzech warstw
kontroli: parsera statycznego, detonacji w izolowanym kontenerze Dockera i oceny
sędziego LLM.

Instrukcja instalacji i użycia: [`SAFE_LOAD_MODEL/README.md`](SAFE_LOAD_MODEL/README.md).

Wcześniejsza wersja projektu (dashboard Flask, dokumentacja PDF, zestaw testów
pytest) została usunięta z drzewa na rzecz biblioteki. Pliki pozostają w historii
gita, w commicie `712016c` i wcześniejszych.
