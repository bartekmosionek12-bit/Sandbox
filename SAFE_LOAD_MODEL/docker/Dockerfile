# Obraz detonera — minimalny, bez niczego poza Pythonem.
# Payload z pickle'a wykonuje się TUTAJ, nigdy na hoście.
FROM python:3.11-slim

# Jedyne pakiety to biblioteki potrzebne do odtworzenia zwykłych modeli
# (numpy, scikit-learn) — bez nich realny model nie wczytuje się w kontenerze
# i detonacja niczego nie dowodzi. Żadnych narzędzi sieciowych ani
# kompilatorów: im mniej w obrazie, tym mniej payload może wykorzystać.
# 'touch', 'echo' i powłoka pochodzą z obrazu bazowego.
COPY docker/requirements-pickle.txt /tmp/requirements-pickle.txt
RUN pip install --no-cache-dir -r /tmp/requirements-pickle.txt \
    && rm /tmp/requirements-pickle.txt

# Kontekst budowy to katalog główny repo (patrz sandbox_rce/sandbox.py),
# żeby detoner miał jedno źródło prawdy i nie trzeba go było duplikować.
COPY sandbox_rce/detonate.py /opt/detonate.py

# Nieuprzywilejowany użytkownik. Razem z --cap-drop=ALL i --read-only
# na hoście daje to detonację bez praw do niczego poza /tmp (tmpfs).
RUN useradd --create-home --shell /usr/sbin/nologin detoner
USER detoner

WORKDIR /tmp

# -I: tryb izolowany (ignoruje PYTHONPATH i katalog użytkownika)
# -u: bez buforowania, żeby log zdążył wyjść przed ewentualnym zabiciem
ENTRYPOINT ["python", "-I", "-u", "/opt/detonate.py"]
