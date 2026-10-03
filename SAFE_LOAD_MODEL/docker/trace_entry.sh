#!/bin/sh
# Wrapper trybu sledzenia: odpala detoner pod strace i dokleja log syscalli
# do stdout, oddzielony markerami, zeby host mogl go wyciac.
#
# Log strace NIE moze lezec w /tmp: detoner porownuje zawartosc /tmp przed
# i po detonacji, zeby pokazac skutek payloadu, wiec wlasny plik strace
# zostalby zaraportowany jako "payload utworzyl". Dlatego osobny tmpfs
# /trace, montowany przez hosta.
set -u

TRACE_OUT=/trace/strace.out

# Waska lista syscalli. Pelny strace na starcie Pythona to tysiace linii
# importow; filtrowanie po stronie strace jest tansze niz po stronie parsera.
SYSCALLS=execve,execveat,connect,sendto,sendmsg,socket,ptrace,chmod,fchmodat,unlink,unlinkat,open,openat,creat

strace -f -qq -s 256 -o "$TRACE_OUT" -e "trace=$SYSCALLS" \
    python -I -u /opt/detonate.py "$1"
rc=$?

echo "@@STRACE_BEGIN@@"
if [ -f "$TRACE_OUT" ]; then
    cat "$TRACE_OUT"
else
    # Brak pliku znaczy, ze strace nie wystartowal. Host MUSI to zobaczyc,
    # bo inaczej pusta lista syscalli wygladalaby jak "payload nic nie robil".
    echo "@@STRACE_UNAVAILABLE@@ strace nie zapisal logu"
fi
echo "@@STRACE_END@@"

exit $rc
