"""Diagnostyka sędziego LLM — mówi, KTÓRY krok nie działa.

„Sędzia niedostępny" na dashboardzie ma pięć różnych przyczyn i z samego
komunikatu nie da się ich rozróżnić. Ten skrypt przechodzi je po kolei
i zatrzymuje się na pierwszej, która nie przechodzi:

1. zmienna ``ANTHROPIC_API_KEY`` nie jest widoczna dla tego procesu,
2. pakiet ``anthropic`` nie jest zainstalowany,
3. wersja SDK jest za stara i nie zna parametru ``output_config``
   (``requirements.txt`` dopuszcza ``>=0.40``, a ten parametr jest dużo
   nowszy — to najbardziej podstępny przypadek, bo klucz jest poprawny,
   a wywołanie i tak się wywala),
4. klucz jest odrzucany przez API albo konto nie ma środków,
5. model z ``JUDGE_MODEL`` nie jest dostępny na tym koncie.

Uruchomienie: ``python tools\\check_judge.py``

Krok 4 wykonuje JEDNO prawdziwe wywołanie API na kilkudziesięciu tokenach,
czyli koszt rzędu dziesiątych części centa.
"""

from __future__ import annotations

import inspect
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _ok(message: str) -> None:
    print(f"  [ OK ] {message}")


def _fail(message: str, fix: str) -> None:
    print(f"  [BLAD] {message}")
    print(f"         -> {fix}")


def main() -> int:
    print("Diagnostyka sedziego LLM")
    print("=" * 60)

    # --- 1. klucz w środowisku TEGO procesu --------------------------------
    print("\n1. Zmienna ANTHROPIC_API_KEY")
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        _fail(
            "zmienna nie jest widoczna dla tego procesu",
            'ustaw ja w TYM okienku: $env:ANTHROPIC_API_KEY = "klucz", '
            "a potem uruchom ten skrypt ponownie",
        )
        return 1
    _ok(f"widoczna, dlugosc {len(key)} znakow, zaczyna sie na {key[:7]}...")
    if key.strip() != key:
        _fail(
            "klucz ma spacje lub znak nowej linii na brzegu",
            "ustaw go ponownie, uwazajac na cudzyslowy przy wklejaniu",
        )
        return 1

    # --- 2. pakiet anthropic ----------------------------------------------
    print("\n2. Pakiet anthropic")
    try:
        import anthropic
    except ImportError as exc:
        _fail(f"brak pakietu ({exc})", "pip install -r requirements.txt")
        return 1
    version = getattr(anthropic, "__version__", "nieznana")
    _ok(f"zainstalowany, wersja {version}")

    # --- 3. czy SDK zna output_config -------------------------------------
    print("\n3. Parametr output_config w SDK")
    try:
        signature = inspect.signature(anthropic.Anthropic(api_key="x").messages.create)
        has_output_config = "output_config" in signature.parameters
    except Exception as exc:  # noqa: BLE001
        print(f"  [INFO] nie udalo sie odczytac sygnatury ({exc}), probuje dalej")
        has_output_config = True
    if not has_output_config:
        _fail(
            f"SDK {version} nie zna parametru output_config, ktorego uzywa sedzia",
            'pip install --upgrade "anthropic>=0.125,<1.0"',
        )
        return 1
    _ok("obecny")

    # --- 4. i 5. prawdziwe wywołanie --------------------------------------
    from sandbox_rce import judge as judge_mod

    model = judge_mod.DEFAULT_MODEL
    print(f"\n4. Prawdziwe wywolanie API, model {model}")
    try:
        client = anthropic.Anthropic(api_key=key)
        response = client.messages.create(
            model=model,
            max_tokens=16,
            messages=[{"role": "user", "content": "Odpowiedz jednym slowem: dziala"}],
        )
        text = next((b.text for b in response.content if b.type == "text"), "")
        _ok(f"API odpowiedzialo: {text.strip()[:40]!r}")
        usage = getattr(response, "usage", None)
        if usage is not None:
            _ok(
                f"tokeny: wejscie {usage.input_tokens}, wyjscie {usage.output_tokens}"
            )
    except Exception as exc:  # noqa: BLE001
        detail = f"{type(exc).__name__}: {exc}"
        print(f"  [BLAD] wywolanie nie przeszlo")
        print(f"         {detail}")
        lowered = detail.lower()
        if "authentication" in lowered or "401" in lowered or "invalid x-api-key" in lowered:
            print("         -> klucz jest odrzucany: sprawdz, czy skopiowal sie caly")
        elif "credit" in lowered or "billing" in lowered or "quota" in lowered:
            print("         -> konto nie ma srodkow: dokup kredyty w konsoli")
        elif "not_found" in lowered or "404" in lowered or "model" in lowered:
            print(
                f'         -> model {model} niedostepny na tym koncie: '
                '$env:JUDGE_MODEL = "claude-sonnet-5" i jeszcze raz'
            )
        elif "output_config" in lowered or "unexpected keyword" in lowered:
            print('         -> stare SDK: pip install --upgrade "anthropic>=0.125,<1.0"')
        else:
            print("         -> wklej te dwie linie, dobierzemy sie do przyczyny")
        return 1

    # --- pelna sciezka sedziego -------------------------------------------
    print("\n5. Pelne wywolanie sedziego na prawdziwym kontrakcie")
    from sandbox_rce import parser as parser_mod
    from sandbox_rce import sandbox as sandbox_mod

    sample = os.path.join(ROOT, "poc", "samples", "evil_os_system.pkl")
    if not os.path.exists(sample):
        print("  [INFO] brak poc/samples/evil_os_system.pkl, pomijam")
        print("         -> python -m poc.build_poc")
        return 0

    parser_report = parser_mod.parse_file(sample)
    sandbox_report = sandbox_mod._empty_report(
        "evil_os_system.pkl", "diagnostyka: bez detonacji"
    )
    verdict = judge_mod.judge(parser_report, sandbox_report)
    if not verdict.get("available"):
        _fail(
            f"sedzia zwrocil available=false: {verdict.get('reasoning')}",
            "wklej ta linie, to jest dokladna przyczyna",
        )
        return 1
    _ok(f"werdykt: {verdict.get('verdict')}, model {verdict.get('model')}")
    print("\n" + "=" * 60)
    print("Sedzia dziala. Jesli dashboard nadal pisze, ze jest niedostepny,")
    print("to serwer wystartowal BEZ tej zmiennej — zatrzymaj go i uruchom")
    print("z tego samego okienka, w ktorym ten skrypt wlasnie przeszedl.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
