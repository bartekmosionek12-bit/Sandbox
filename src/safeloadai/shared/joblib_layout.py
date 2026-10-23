"""joblib's array layout, shared by the static walker (host), the recording unpickler
(inside the WASI sandbox) and the restricted loader behind ``safe_load``.

Standard library only, compatible with the guest's CPython 3.12. Nothing here
reads a file or builds an object; it only turns the values that a pickle stream
put into a ``NumpyArrayWrapper`` into the number of raw bytes joblib reads next.

What joblib does (joblib/numpy_pickle.py, 1.x): ``NumpyPickler.save`` pickles a
``NumpyArrayWrapper`` (subclass, shape, order, dtype, allow_mmap and, since 1.2,
numpy_array_alignment_bytes) instead of each ndarray, commits the pickle frame and
writes the array right behind it in the same stream:

* dtype without Python objects: if ``numpy_array_alignment_bytes`` is not None,
  one byte N followed by N padding bytes, then ``prod(shape) * itemsize`` raw
  bytes;
* dtype with Python objects: a complete nested pickle of the array, which joblib
  reads with a fresh plain Unpickler (no array hook) that shares the outer
  ``find_class``.

``NumpyUnpickler.load_build`` runs the normal BUILD and, if the object on top of the
stack is then a wrapper, replaces it with the array it reads. Anything this module
cannot account for exactly raises LayoutError, and the caller fails closed.
"""

WRAPPER = ("joblib.numpy_pickle", "NumpyArrayWrapper")
# joblib < 0.10: arrays live in side files (*.npy, *.z) next to the main pickle.
LEGACY_WRAPPERS = frozenset({
    ("joblib.numpy_pickle", "NDArrayWrapper"),
    ("joblib.numpy_pickle", "ZNDArrayWrapper"),
    ("joblib.numpy_pickle_compat", "NDArrayWrapper"),
    ("joblib.numpy_pickle_compat", "ZNDArrayWrapper"),
})
DTYPE = ("numpy", "dtype")

MAX_DIMS = 64
MAX_DTYPE_DEPTH = 8
MAX_FIELDS = 4096
NPY_ITEM_HASOBJECT = 0x01

# Fixed-size kinds and the sizes numpy uses for them (descr strings like "f8").
_FIXED = {
    "b": (1,),
    "i": (1, 2, 4, 8),
    "u": (1, 2, 4, 8),
    "f": (2, 4, 8, 10, 12, 16),
    "c": (8, 16, 20, 24, 32),
    "M": (8,),
    "m": (8,),
}
_ENDIAN = frozenset("<>|=")


class LayoutError(ValueError):
    """The wrapper or dtype is not one joblib's reader handles in a known way."""


def dtype_flags_ok(align, copy):
    """The ``align`` and ``copy`` arguments of a pickled ``numpy.dtype(descr, align, copy)``.
    numpy writes ``False, True``; older numpy wrote the ints ``0, 1``, which mean the same."""
    return (type(align) in (bool, int) and align == 0
            and type(copy) in (bool, int) and copy == 1)


class Plan:
    """What follows a wrapper's BUILD in the stream."""

    __slots__ = ("padding", "nbytes", "hasobject", "shape", "order", "itemsize")

    def __init__(self, padding, nbytes, hasobject, shape, order, itemsize):
        self.padding = padding
        self.nbytes = nbytes
        self.hasobject = hasobject
        self.shape = shape
        self.order = order
        self.itemsize = itemsize

    def __repr__(self):
        return "Plan(padding=%r, nbytes=%r, hasobject=%r, shape=%r, order=%r)" % (
            self.padding, self.nbytes, self.hasobject, self.shape, self.order)


def _is_int(value):
    return type(value) is int


def _split_descr(descr):
    if not isinstance(descr, str) or not descr:
        raise LayoutError("dtype descriptor is not a string: %r" % (descr,))
    kind, digits = descr[0], descr[1:]
    if not digits.isdigit() or len(digits) > 12:
        raise LayoutError("unsupported dtype descriptor %r" % (descr,))
    return kind, int(digits)


def dtype_layout(descr, state, field_dtype, depth=0):
    """(itemsize, hasobject) of the dtype numpy rebuilds from
    ``numpy.dtype(descr, False, True)`` followed by ``__setstate__(state)``.

    ``field_dtype(value)`` returns ``(descr, state)`` for a nested dtype value found
    in ``fields`` or ``subarray`` (or raises LayoutError).
    """
    if depth > MAX_DTYPE_DEPTH:
        raise LayoutError("dtype nested more than %d levels" % MAX_DTYPE_DEPTH)
    if not isinstance(state, tuple) or len(state) not in (8, 9):
        raise LayoutError("unexpected dtype state %r" % (type(state).__name__,))
    version, endian, subarray, names, fields, elsize, alignment, flags = state[:8]
    if version not in (3, 4) or (version == 3) != (len(state) == 8):
        raise LayoutError("unsupported dtype state version %r" % (version,))
    if endian not in _ENDIAN:
        raise LayoutError("unsupported dtype byte order %r" % (endian,))
    if not (_is_int(elsize) and _is_int(alignment) and _is_int(flags)):
        raise LayoutError("dtype sizes are not integers")
    kind, size = _split_descr(descr)
    object_flag = bool(flags & NPY_ITEM_HASOBJECT)

    if kind == "O":
        if subarray is not None or names is not None or fields is not None or elsize != -1:
            raise LayoutError("object dtype with structure")
        if size not in (4, 8) or not object_flag:
            raise LayoutError("inconsistent object dtype %r flags %r" % (descr, flags))
        return size, True

    if kind in _FIXED:
        if size not in _FIXED[kind]:
            raise LayoutError("unsupported dtype %r" % (descr,))
        if subarray is not None or names is not None or fields is not None or elsize != -1:
            raise LayoutError("fixed-size dtype %r with structure" % (descr,))
        if object_flag:
            raise LayoutError("dtype %r flagged as holding objects" % (descr,))
        return size, False

    if kind in ("S", "U"):
        expected = size * (4 if kind == "U" else 1)
        if elsize != expected or subarray is not None or names is not None or fields is not None:
            raise LayoutError("inconsistent string dtype %r (elsize %r)" % (descr, elsize))
        if object_flag:
            raise LayoutError("string dtype flagged as holding objects")
        return elsize, False

    if kind == "V":
        if elsize != size or size < 0:
            raise LayoutError("inconsistent void dtype %r (elsize %r)" % (descr, elsize))
        if object_flag:
            raise LayoutError("structured dtype with Python objects is not supported")
        if subarray is not None:
            if names is not None or fields is not None:
                raise LayoutError("dtype with both subarray and fields")
            if not (isinstance(subarray, tuple) and len(subarray) == 2):
                raise LayoutError("malformed dtype subarray")
            base, sub_shape = subarray
            base_size, base_object = dtype_layout(*field_dtype(base), field_dtype, depth + 1)
            count = shape_count(sub_shape if isinstance(sub_shape, tuple) else (sub_shape,))
            if base_object or base_size * count != elsize:
                raise LayoutError("subarray dtype does not add up to its size")
            return elsize, False
        if (names is None) != (fields is None):
            raise LayoutError("dtype names without fields (or the reverse)")
        if names is not None:
            if not (isinstance(names, tuple) and isinstance(fields, dict)):
                raise LayoutError("malformed dtype fields")
            if len(names) > MAX_FIELDS or set(names) != set(fields) or len(set(names)) != len(names):
                raise LayoutError("dtype names do not match its fields")
            for name in names:
                entry = fields[name]
                if not (isinstance(entry, tuple) and len(entry) in (2, 3) and _is_int(entry[1])):
                    raise LayoutError("malformed dtype field %r" % (name,))
                sub_size, sub_object = dtype_layout(*field_dtype(entry[0]), field_dtype, depth + 1)
                if sub_object:
                    raise LayoutError("structured dtype with Python objects is not supported")
                if entry[1] < 0 or entry[1] + sub_size > elsize:
                    raise LayoutError("dtype field %r lies outside the item" % (name,))
        return elsize, False

    raise LayoutError("unsupported dtype kind %r" % (descr,))


def shape_count(shape):
    if not isinstance(shape, (tuple, list)) or len(shape) > MAX_DIMS:
        raise LayoutError("array shape is not a short tuple: %r" % (type(shape).__name__,))
    count = 1
    for dim in shape:
        if not _is_int(dim) or dim < 0:
            raise LayoutError("array dimension is not a non-negative int: %r" % (dim,))
        count *= dim
    return count


def plan(attrs, dtype_of, field_dtype):
    """Plan for one wrapper from its attribute dict (the BUILD state).

    ``dtype_of(value)`` returns ``(descr, state)`` for the wrapper's ``dtype``
    attribute; ``field_dtype`` is passed on to :func:`dtype_layout`.
    """
    if not isinstance(attrs, dict):
        raise LayoutError("NumpyArrayWrapper state is not a dict")
    for key in ("shape", "order", "dtype"):
        if key not in attrs:
            raise LayoutError("NumpyArrayWrapper state lacks %r" % key)
    order = attrs["order"]
    if order not in ("C", "F"):
        raise LayoutError("unsupported array order %r" % (order,))
    itemsize, hasobject = dtype_layout(*dtype_of(attrs["dtype"]), field_dtype)
    count = shape_count(attrs["shape"])
    padding = attrs.get("numpy_array_alignment_bytes") is not None
    nbytes = None if hasobject else count * itemsize
    return Plan(padding, nbytes, hasobject, tuple(attrs["shape"]), order, itemsize)
