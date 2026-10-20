"""A pickle machine that tracks values without ever creating an object.

``pickletools.genops`` only decodes opcodes. This module runs them against a stack
and a memo of inert stand-ins: Python data for the data opcodes (ints, strings,
tuples, lists, dicts...), :class:`Global` for an import and :class:`Obj` for
anything a call or BUILD would produce. Nothing is imported or called. That is
enough to resolve ``STACK_GLOBAL`` through the memo, to read the state of a
joblib ``NumpyArrayWrapper`` and skip the raw array bytes joblib writes after it,
and to notice the things that make a real unpickler fail (stack underflow, a
missing memo entry, a bad frame).

Frames follow the pure-Python unpickler: a new FRAME before the current one is
used up, an opcode that crosses the end of a frame, a STOP or array data before
the end of a frame are all errors here, because a real unpickler either fails
there or reads different bytes than a sequential walk would.
"""
from __future__ import annotations

import io
import pickletools
import re

from ..shared import joblib_layout

MARK = object()
HIGHEST_PROTOCOL = 5
_IDENTIFIER_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_RECONSTRUCTOR = ("copyreg", "_reconstructor")
_OBJECT = ("builtins", "object")


class VMError(Exception):
    """The stream is one a real unpickler would reject (or read differently)."""


class Global:
    __slots__ = ("module", "name")

    def __init__(self, module, name):
        self.module, self.name = module, name

    @property
    def pair(self):
        return (self.module, self.name)


class Obj:
    """Result of REDUCE / NEWOBJ / OBJ / INST / EXT / PERSID, or an array joblib read."""

    __slots__ = ("how", "func", "args", "state", "attrs")

    def __init__(self, how, func=None, args=None):
        self.how, self.func, self.args = how, func, args
        self.state = None
        self.attrs = None


def identifier_path(text) -> bool:
    return isinstance(text, str) and bool(_IDENTIFIER_PATH.match(text))


def class_of(obj):
    """(module, name) of the class an Obj is an instance of, when the opcodes say so."""
    if not isinstance(obj, Obj) or not isinstance(obj.func, Global):
        return None
    if obj.how in ("newobj", "newobj_ex", "obj", "inst"):
        return obj.func.pair
    if obj.how == "reduce":
        if obj.func.pair == _RECONSTRUCTOR and isinstance(obj.args, tuple) and len(obj.args) == 3 \
                and isinstance(obj.args[0], Global):
            return obj.args[0].pair
        return obj.func.pair
    return None


def dtype_value(value):
    """(descr, state) of a ``numpy.dtype(descr, False, True)`` + BUILD stand-in."""
    if not (isinstance(value, Obj) and value.how == "reduce" and isinstance(value.func, Global)
            and value.func.pair == joblib_layout.DTYPE):
        raise joblib_layout.LayoutError("array dtype is not a numpy.dtype reconstruction")
    args = value.args
    if not (isinstance(args, tuple) and len(args) == 3 and args[1] is False and args[2] is True):
        raise joblib_layout.LayoutError("unexpected numpy.dtype arguments")
    return args[0], value.state


class Machine:
    """Walks pickles from ``stream`` (a BytesIO over the whole file).

    ``on_import(module, name, pos, opcode, resolved)``, ``on_opcode(op, arg, pos)`` and
    ``on_call(how, func, args, pos)`` are callbacks; ``on_call`` sees every opcode that
    would call something (REDUCE, NEWOBJ, NEWOBJ_EX, OBJ, INST, and BUILD with
    ``args == (state,)``). With ``joblib=True`` BUILD on a NumpyArrayWrapper skips (or, for
    object dtypes, walks as a nested pickle) the array data that follows, exactly as
    ``joblib.numpy_pickle.NumpyUnpickler`` reads it.
    """

    def __init__(self, data: bytes, *, joblib: bool = True, on_import=None, on_opcode=None,
                 on_call=None, max_opcodes: int = 5_000_000):
        self.data = data
        self.stream = io.BytesIO(data)
        self.joblib = joblib
        self.on_import = on_import or (lambda *a: None)
        self.on_opcode = on_opcode or (lambda *a: None)
        self.on_call = on_call or (lambda *a: None)
        self.max_opcodes = max_opcodes
        self.opcodes = 0
        self.arrays = 0
        self.object_arrays = 0
        self.array_bytes = 0
        self.legacy_wrappers = 0
        self.first_region = None  # (stack, memo) snapshot where joblib's reading first diverges
        # id -> number of extra references (GET, DUP) to a Global or Obj: a value pushed once
        # and never fetched again is used exactly where it was pushed.
        self.refs: dict[int, int] = {}
        # Every Global the stream creates, by the position of its import opcode, and every
        # way a value reaches code other than a call (on_call): (kind, value, target, pos)
        # with kind "append" or "setitem" (into an Obj, so a method of its class runs),
        # "key" (a dict key or set member is hashed) or "persid" (persistent_load gets it).
        self.globals: dict[int, Global] = {}
        self.uses: list[tuple] = []
        # The value each pickle returns (what STOP pops), in reading order.
        self.results: list = []

    # --- one pickle ---------------------------------------------------------------

    def run_one(self, *, nested: bool = False):
        """Walk one pickle up to its STOP. Returns (stop_reached, first_int)."""
        stack: list = []
        memo: dict = {}
        state = {"frame_end": None, "first_int": None}
        for opcode, arg, pos in pickletools.genops(self.stream):
            end = self.stream.tell()
            self.opcodes += 1
            if self.opcodes > self.max_opcodes:
                raise VMError(f"more than {self.max_opcodes} opcodes")
            self._frames(opcode.name, arg, pos, end, state)
            self.on_opcode(opcode, arg, pos)
            if state["first_int"] is None and isinstance(arg, int) and not isinstance(arg, bool) \
                    and opcode.name in ("LONG1", "LONG4", "LONG", "INT", "BININT", "BININT1", "BININT2"):
                state["first_int"] = arg
            if opcode.name == "STOP":
                if state["frame_end"] is not None and end < state["frame_end"]:
                    raise VMError(f"STOP at {pos} before the end of its frame (bytes would be skipped)")
                self.results.append(self._pop(stack))
                if stack:
                    pass  # leftover items: real unpicklers ignore them
                return True, state["first_int"]
            self._step(opcode.name, arg, pos, end, stack, memo, state, nested)
        return False, state["first_int"]

    def _frames(self, name, arg, pos, end, state):
        frame_end = state["frame_end"]
        if frame_end is not None:
            if pos >= frame_end:
                state["frame_end"] = frame_end = None
            elif end > frame_end:
                raise VMError(f"{name} at {pos} crosses the end of its frame at {frame_end}")
        if name == "FRAME":
            if frame_end is not None:
                raise VMError(f"FRAME at {pos} before the end of the current frame")
            state["frame_end"] = end + int(arg)
            if state["frame_end"] > len(self.data):
                raise VMError(f"FRAME at {pos} extends past the end of the file")

    # --- stack helpers --------------------------------------------------------------

    @staticmethod
    def _pop(stack):
        if not stack or stack[-1] is MARK:
            raise VMError("unpickling stack underflow")
        return stack.pop()

    @staticmethod
    def _top(stack):
        if not stack or stack[-1] is MARK:
            raise VMError("unpickling stack underflow")
        return stack[-1]

    @staticmethod
    def _pop_mark(stack):
        items = []
        while stack:
            item = stack.pop()
            if item is MARK:
                items.reverse()
                return items
            items.append(item)
        raise VMError("could not find MARK")

    # --- opcode semantics -----------------------------------------------------------

    def _step(self, name, arg, pos, end, stack, memo, state, nested):  # noqa: C901 - one table
        pop, top, pop_mark = self._pop, self._top, self._pop_mark
        if name in ("PROTO",):
            if not isinstance(arg, int) or arg > HIGHEST_PROTOCOL:
                raise VMError(f"unsupported pickle protocol {arg!r}")
        elif name == "FRAME":
            pass
        elif name in ("INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "FLOAT", "BINFLOAT",
                      "STRING", "BINSTRING", "SHORT_BINSTRING", "BINBYTES", "SHORT_BINBYTES", "BINBYTES8",
                      "BYTEARRAY8", "UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8"):
            stack.append(arg)
        elif name == "NONE":
            stack.append(None)
        elif name == "NEWTRUE":
            stack.append(True)
        elif name == "NEWFALSE":
            stack.append(False)
        elif name == "NEXT_BUFFER":
            raise VMError("out-of-band buffer (NEXT_BUFFER) without a buffer source")
        elif name == "READONLY_BUFFER":
            top(stack)
        elif name == "EMPTY_LIST":
            stack.append([])
        elif name == "EMPTY_DICT":
            stack.append({})
        elif name == "EMPTY_TUPLE":
            stack.append(())
        elif name == "EMPTY_SET":
            stack.append(set())
        elif name == "MARK":
            stack.append(MARK)
        elif name == "POP":
            if stack and stack[-1] is MARK:
                stack.pop()
            else:
                pop(stack)
        elif name == "POP_MARK":
            pop_mark(stack)
        elif name == "DUP":
            stack.append(self._ref(top(stack)))
        elif name in ("TUPLE1", "TUPLE2", "TUPLE3"):
            n = int(name[-1])
            items = [pop(stack) for _ in range(n)][::-1]
            stack.append(tuple(items))
        elif name == "TUPLE":
            stack.append(tuple(pop_mark(stack)))
        elif name == "LIST":
            stack.append(pop_mark(stack))
        elif name == "DICT":
            items = pop_mark(stack)
            if len(items) % 2:
                raise VMError("odd number of items for DICT")
            stack.append(self._dict(items))
        elif name == "FROZENSET":
            items = pop_mark(stack)
            self.uses.append(("key", tuple(items), None, pos))
            stack.append(self._hashable(frozenset, items))
        elif name == "APPEND":
            value = pop(stack)
            target = top(stack)
            if isinstance(target, list):
                target.append(value)
            else:
                self.uses.append(("append", (value,), target, pos))
        elif name == "APPENDS":
            items = pop_mark(stack)
            target = top(stack)
            if isinstance(target, list):
                target.extend(items)
            else:
                self.uses.append(("append", tuple(items), target, pos))
        elif name == "SETITEM":
            value, key = pop(stack), pop(stack)
            target = top(stack)
            if isinstance(target, dict):
                self._setitem(target, key, value)
            else:
                self.uses.append(("setitem", (key, value), target, pos))
        elif name == "SETITEMS":
            items = pop_mark(stack)
            if len(items) % 2:
                raise VMError("odd number of items for SETITEMS")
            target = top(stack)
            if isinstance(target, dict):
                for i in range(0, len(items), 2):
                    self._setitem(target, items[i], items[i + 1])
            else:
                self.uses.append(("setitem", tuple(items), target, pos))
        elif name == "ADDITEMS":
            items = pop_mark(stack)
            target = top(stack)
            self.uses.append(("key", tuple(items), target, pos))
            if isinstance(target, set):
                for item in items:
                    self._hashable(target.add, item)
        elif name in ("GET", "BINGET", "LONG_BINGET"):
            if arg not in memo:
                raise VMError(f"memo key {arg!r} not found")
            stack.append(self._ref(memo[arg]))
        elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
            if not isinstance(arg, int) or arg < 0:
                raise VMError("negative PUT argument")
            memo[arg] = top(stack)
        elif name == "MEMOIZE":
            memo[len(memo)] = top(stack)
        elif name in ("GLOBAL", "INST"):
            parts = str(arg).replace("\n", " ").split()
            resolved = len(parts) == 2
            module, qualname = (parts if resolved else (None, None))
            self.on_import(module, qualname, pos, name, resolved)
            func = Global(module, qualname)
            self.globals[pos] = func
            if name == "GLOBAL":
                stack.append(func)
            else:
                args = tuple(pop_mark(stack))
                self.on_call("inst", func, args, pos)
                stack.append(Obj("inst", func, args))
        elif name == "STACK_GLOBAL":
            qualname, module = pop(stack), pop(stack)
            resolved = isinstance(module, str) and isinstance(qualname, str)
            self.on_import(module if resolved else None, qualname if resolved else None, pos, name, resolved)
            if not resolved:
                raise VMError("STACK_GLOBAL requires str")
            func = Global(module, qualname)
            self.globals[pos] = func
            stack.append(func)
        elif name == "REDUCE":
            args, func = pop(stack), pop(stack)
            if not isinstance(args, tuple):
                raise VMError("REDUCE arguments are not a tuple")
            self.on_call("reduce", func, args, pos)
            stack.append(Obj("reduce", func, args))
        elif name == "NEWOBJ":
            args, cls = pop(stack), pop(stack)
            self.on_call("newobj", cls, args, pos)
            stack.append(Obj("newobj", cls, args))
        elif name == "NEWOBJ_EX":
            kwargs, args, cls = pop(stack), pop(stack), pop(stack)
            self.on_call("newobj_ex", cls, (args, kwargs), pos)
            stack.append(Obj("newobj_ex", cls, (args, kwargs)))
        elif name == "OBJ":
            items = pop_mark(stack)
            if not items:
                raise VMError("OBJ without a class")
            self.on_call("obj", items[0], tuple(items[1:]), pos)
            stack.append(Obj("obj", items[0], tuple(items[1:])))
        elif name == "BUILD":
            build_state = pop(stack)
            target = top(stack)
            self.on_call("build", target, (build_state,), pos)
            if isinstance(target, Obj):
                target.state = build_state
            self._after_build(stack, memo, pos, end, state, nested)
        elif name in ("EXT1", "EXT2", "EXT4"):
            stack.append(Obj("ext", None, (arg,)))
        elif name == "PERSID":
            stack.append(Obj("persid", None, (arg,)))
        elif name == "BINPERSID":
            pid = pop(stack)
            self.uses.append(("persid", (pid,), None, pos))
            stack.append(Obj("persid", None, (pid,)))
        else:
            raise VMError(f"opcode {name} is not modelled")

    def _ref(self, value):
        if isinstance(value, (Global, Obj)):
            self.refs[id(value)] = self.refs.get(id(value), 0) + 1
        return value

    def _dict(self, items):
        out = {}
        for i in range(0, len(items), 2):
            self._setitem(out, items[i], items[i + 1])
        return out

    def _setitem(self, target, key, value):
        if isinstance(key, (Global, Obj, tuple, frozenset)):
            self.uses.append(("key", (key,), target, None))
        try:
            target[key] = value
        except TypeError as exc:
            raise VMError(f"unhashable dict key: {exc}") from exc

    @staticmethod
    def _hashable(func, value):
        try:
            return func(value)
        except TypeError as exc:
            raise VMError(f"unhashable item: {exc}") from exc

    # --- joblib -----------------------------------------------------------------------

    def _after_build(self, stack, memo, pos, end, state, nested):
        if not self.joblib or nested:
            return
        obj = stack[-1]
        cls = class_of(obj)
        if cls in joblib_layout.LEGACY_WRAPPERS:
            self.legacy_wrappers += 1
            return
        if cls != joblib_layout.WRAPPER:
            return
        plain = (obj.how == "newobj" and obj.args == ()) or (
            obj.how == "reduce" and obj.func.pair == _RECONSTRUCTOR and len(obj.args) == 3
            and isinstance(obj.args[1], Global) and obj.args[1].pair == _OBJECT and obj.args[2] is None)
        if not plain:
            raise VMError(f"NumpyArrayWrapper at {pos} built in an unsupported way ({obj.how})")
        if not isinstance(obj.state, dict):
            raise VMError(f"NumpyArrayWrapper at {pos} has a non-dict state")
        if obj.attrs is None:
            obj.attrs = {}
        obj.attrs.update(obj.state)
        if state["frame_end"] is not None and end < state["frame_end"]:
            raise VMError(f"array data at {end} inside a pickle frame (ends at {state['frame_end']})")
        try:
            plan = joblib_layout.plan(obj.attrs, dtype_value, dtype_value)
        except joblib_layout.LayoutError as exc:
            raise VMError(f"NumpyArrayWrapper at {pos}: {exc}") from exc
        if self.first_region is None:
            self.first_region = (end, list(stack), dict(memo))
        stack[-1] = Obj("array", None, (plan,))
        if plan.hasobject:
            self.object_arrays += 1
            stop, _ = self.run_one(nested=True)
            if not stop:
                raise VMError(f"object array at {end}: nested pickle ends without STOP")
            return
        cursor = end
        if plan.padding:
            if cursor >= len(self.data):
                raise VMError(f"array at {end}: missing alignment byte")
            cursor += 1 + self.data[cursor]
        if cursor + plan.nbytes > len(self.data):
            raise VMError(f"array at {end}: {plan.nbytes} bytes of data announced, "
                          f"{max(len(self.data) - cursor, 0)} left in the file")
        self.arrays += 1
        self.array_bytes += plan.nbytes
        self.stream.seek(cursor + plan.nbytes)


def plain_reading_imports(data: bytes, region, max_opcodes: int = 5_000_000,
                          on_call=None) -> tuple[list[tuple], bool]:
    """Imports a plain ``pickle.load`` would perform from where joblib starts reading
    array data: it interprets those bytes as opcodes, with the same stack and memo.

    Returns (module, name, pos, opcode) for imports whose names are identifier paths
    (anything else cannot be imported) and for EXT opcodes (module None). The walk
    stops at the first opcode a real unpickler would reject. The second value is
    False when the walk ran out of budget before such a point (undecided).
    """
    start, stack, memo = region
    found: list[tuple] = []

    def on_import(module, name, pos, opcode, resolved):
        if resolved and identifier_path(module) and identifier_path(name):
            found.append((module, name, pos, opcode))

    def on_opcode(opcode, arg, pos):
        if opcode.name in ("EXT1", "EXT2", "EXT4"):
            found.append((None, None, pos, opcode.name))

    machine = Machine(data, joblib=False, on_import=on_import, on_opcode=on_opcode, on_call=on_call,
                      max_opcodes=max_opcodes)
    machine.stream.seek(start)
    state = {"frame_end": None, "first_int": None}
    stack, memo = list(stack), dict(memo)
    decided = True
    try:
        for opcode, arg, pos in pickletools.genops(machine.stream):
            end = machine.stream.tell()
            machine.opcodes += 1
            if machine.opcodes > max_opcodes:
                decided = False
                break
            machine._frames(opcode.name, arg, pos, end, state)
            on_opcode(opcode, arg, pos)
            if opcode.name == "STOP":
                break
            machine._step(opcode.name, arg, pos, end, stack, memo, state, True)
    except (VMError, ValueError, TypeError, IndexError, OverflowError, UnicodeDecodeError):
        pass
    return found, decided
