from collections import OrderedDict
from typing import Dict

import numpy as np


class MatchingCache:
    """A reduced in-memory view for a selection of FunctionEntry and corresponding SampleEntry objects - implements a subset of StorageInterface"""

    def __init__(self, cache_data):
        self._func_id_to_minhash = cache_data["func_id_to_minhash"]
        self._func_id_to_sample_id = cache_data["func_id_to_sample_id"]
        self._sample_id_to_func_ids = cache_data["sample_id_to_func_ids"]
        # bumped whenever the held minhashes change, so the signature matrix can be reused
        # across the batches of a job without ever serving a stale row
        self._version = 0
        self._signature_view = None
        self._signature_version = None
        # function_ids fetched from storage (and therefore evictable), in
        # least-recently-needed order; lives on the cache so that the cache and its LRU
        # bookkeeping share one scope - the job/matcher that owns this object
        self._evictable = OrderedDict()

    def invalidateSignatureMatrix(self):
        """Callers that mutate _func_id_to_minhash directly must announce it."""
        self._version += 1
        self._signature_view = None

    def getSignatureMatrix(self, signature_length=64, signature_bits=8):
        """(sorted_function_ids, row_index_for_each, minhash_matrix) for vectorised scoring.

        The matrix is built in dict order and left there; only the id array is sorted, with
        `rows` mapping a searchsorted position back to its matrix row. Sorting the matrix
        itself would cost a full extra copy of it for no benefit.
        """
        memo_key = (self._version, signature_length, signature_bits)
        if self._signature_view is not None and self._signature_version == memo_key:
            return self._signature_view
        # release the previous matrix before allocating the next one, or the rebuild holds two
        # full copies of every retained signature at once
        self._signature_view = None
        dtype = np.uint8 if signature_bits <= 8 else np.uint32
        entry_bytes = signature_length * np.dtype(dtype).itemsize
        # Filter per entry, never by aggregate byte count: entries whose lengths happen to sum
        # to a multiple of entry_bytes would pass an aggregate check and silently shift every
        # row after the first mismatch. The query matchers legitimately inject b"" for the
        # ~36 % of functions below MINHASH_FN_MIN_INS; those can never be scored, so they are
        # dropped. Any OTHER wrong length means the corpus and the config disagree, which is a
        # configuration error and must be loud.
        kept_ids = []
        kept_minhashes = []
        for function_id, minhash in self._func_id_to_minhash.items():
            if len(minhash) == entry_bytes:
                kept_ids.append(function_id)
                kept_minhashes.append(minhash)
            elif minhash:
                raise ValueError(
                    "MatchingCache: function %d has a %d-byte minhash, expected %d "
                    "(%d x %s) - corpus and MINHASH_SIGNATURE_* configuration disagree" % (function_id, len(minhash), entry_bytes, signature_length, np.dtype(dtype).name)
                )
        function_ids = np.fromiter(kept_ids, dtype=np.int64, count=len(kept_ids))
        # One row per *distinct* signature, not per function. A score depends only on the two
        # signatures, so functions sharing a signature score identically against any query -
        # deduplicating rows is exact, not an approximation, and the row mapping below keeps
        # every function addressable. Corpora duplicate code heavily and increasingly so with
        # size: measured 185,387 hashed functions over 75,323 distinct signatures (2.46x) on
        # 257 real Malpedia samples, and the fitted Heaps' law puts that near 24x at a million.
        # The matrix shrinks by that factor, and so does the comparison work once the scorer
        # collapses repeated rows.
        row_by_signature: Dict[bytes, int] = {}
        unique_minhashes = []
        row_for_entry = []
        for minhash in kept_minhashes:
            row = row_by_signature.get(minhash)
            if row is None:
                row = len(unique_minhashes)
                row_by_signature[minhash] = row
                unique_minhashes.append(minhash)
            row_for_entry.append(row)
        del row_by_signature
        joined = b"".join(unique_minhashes)
        matrix = np.frombuffer(joined, dtype=dtype).reshape(len(unique_minhashes), signature_length)
        entry_rows = np.fromiter(row_for_entry, dtype=np.int64, count=len(row_for_entry))
        order = np.argsort(function_ids, kind="stable")
        # contract is unchanged: rows[searchsorted position of a function id] is its matrix row
        self._signature_view = (function_ids[order], entry_rows[order], matrix)
        self._signature_version = memo_key
        return self._signature_view

    def getRowsForFunctionIds(self, function_ids_array, sorted_ids, rows):
        """Matrix rows for an int64 array of function_ids; raises KeyError on any miss."""
        if sorted_ids.size == 0:
            raise KeyError(int(function_ids_array[0]))
        positions = np.searchsorted(sorted_ids, function_ids_array)
        np.clip(positions, 0, sorted_ids.size - 1, out=positions)
        if not np.array_equal(sorted_ids[positions], function_ids_array):
            missing = function_ids_array[sorted_ids[positions] != function_ids_array]
            raise KeyError(int(missing[0]))
        return rows[positions]

    def _setFunctionEntry(self, function_id, sample_id, minhash):
        self._version += 1
        self._signature_view = None
        if function_id in self._func_id_to_sample_id:
            old_sample_id = self._func_id_to_sample_id[function_id]
            if old_sample_id in self._sample_id_to_func_ids:
                self._sample_id_to_func_ids[old_sample_id].discard(function_id)
                if not self._sample_id_to_func_ids[old_sample_id]:
                    del self._sample_id_to_func_ids[old_sample_id]
        self._func_id_to_minhash[function_id] = minhash
        self._func_id_to_sample_id[function_id] = sample_id
        if sample_id not in self._sample_id_to_func_ids:
            self._sample_id_to_func_ids[sample_id] = set()
        self._sample_id_to_func_ids[sample_id].add(function_id)

    def isSampleId(self, sample_id):
        return sample_id in self._sample_id_to_func_ids

    def getMinHashByFunctionId(self, function_id) -> bytes:
        return self._func_id_to_minhash[function_id]

    def getSampleIdByFunctionId(self, function_id) -> int:
        return self._func_id_to_sample_id[function_id]

    def getFunctionIdsBySampleId(self, sample_id):
        return self._sample_id_to_func_ids[sample_id]

    def addFunctionEntriesToCache(self, function_entries):
        for function_entry in function_entries:
            self._setFunctionEntry(function_entry.function_id, function_entry.sample_id, function_entry.minhash)


class StorageBackedMatchingCache(MatchingCache):
    """A matching cache that reuses storage-backed data without mutating the underlying storage."""

    def __init__(self, storage, function_ids):
        self._storage = storage
        self._version = 0
        self._signature_view = None
        self._signature_version = None
        self._evictable = OrderedDict()
        self._func_id_to_minhash = {}
        unique_function_ids = set(function_ids)
        self._func_id_to_sample_id = dict(self._storage.getSampleIdsByFunctionIds(list(unique_function_ids)))
        self._sample_id_to_func_ids = {}
        missing_function_ids = unique_function_ids.difference(self._func_id_to_sample_id)
        if missing_function_ids:
            raise KeyError(missing_function_ids.pop())
        for function_id, sample_id in self._func_id_to_sample_id.items():
            if sample_id not in self._sample_id_to_func_ids:
                self._sample_id_to_func_ids[sample_id] = set()
            self._sample_id_to_func_ids[sample_id].add(function_id)

    def getMinHashByFunctionId(self, function_id):
        if function_id in self._func_id_to_minhash:
            return self._func_id_to_minhash[function_id]
        if function_id not in self._func_id_to_sample_id:
            raise KeyError(function_id)
        return self._storage.getMinHashByFunctionId(function_id)

    def getSignatureMatrix(self, signature_length=64, signature_bits=8):
        # minhashes are served lazily from storage here, so there is nothing to build a
        # matrix from - callers must fall back to the scalar path
        raise NotImplementedError("StorageBackedMatchingCache does not hold minhashes")
