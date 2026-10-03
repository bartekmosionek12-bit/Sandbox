# Obraz detonera — minimalny, bez niczego poza Pythonem.
# Payload z pickle'a wykonuje się TUTAJ, nigdy na hoście.
FROM python:3.11-slim

# Nie instalujemy żadnych pakietów: im mniej narzędzi w obrazie, tym mniej
# payload może wykorzystać. 'touch', 'echo' i powłoka pochodzą z obrazu bazowego.

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
