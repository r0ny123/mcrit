# Indexing approaches for MCRIT-scale similarity search: comparison and decision

Comparison of the options considered for making 1-vs-N matching scale, judged on latency,
recall, memory, and operational complexity - and, first of all, on whether they estimate the
quantity MCRIT actually matches on.

## The constraint that eliminates most of the field

MCRIT compares **MinHash signatures**: 64 one-byte fields, compared for **exact field
equality**, estimating **Jaccard similarity** over a function's shingled feature set. A score
is `100 * (matching fields) / 64`.

That is not a metric space embedding. Cosine and L2 nearest-neighbour indexes answer a
*different question*, so adopting one does not make MCRIT faster at what it does - it changes
what "similar" means, and the goal explicitly forbids degrading match quality. This rules out
the whole dense-vector ANN family as a drop-in, however good those systems are at their own job.

| Approach | Similarity it indexes | Fits MinHash/Jaccard? | Latency at 1e6+ | Recall | Memory | Ops complexity | Verdict |
|---|---|---|---|---|---|---|---|
| **LSH banding over an inverted index** (what MCRIT has) | Jaccard, exactly | **Yes - native** | Grows with posting-list length | Tunable by bands/rows | Index ~ corpus | Already deployed on MongoDB | **Keep.** The structure is right; the traversal was unbounded |
| FAISS (IVF, IVF-PQ, HNSW) | L2 / inner product | No - needs an embedding | ms at 1e9 (IVF-PQ) | High for its own metric | PQ compresses hard | Library, but sharding/persistence is yours | Rejected: changes the similarity |
| ScaNN | Inner product (anisotropic quantization) | No | Best-in-class ANN throughput | High for its own metric | Compressed | Library, TF-adjacent | Rejected: changes the similarity |
| HNSW (hnswlib, and inside Qdrant/Weaviate/Milvus) | Any metric, in practice L2/cosine | Poorly - graph build assumes a metric with meaningful near-ties | Sub-ms, very high recall | Very high | **High** - graph is RAM-resident | Moderate | Rejected: memory scales badly for a petabyte corpus, and the metric is wrong |
| DiskANN / SPANN | L2 / inner product, SSD-resident | No | ~ms at 1e9 on SSD | High | Low RAM, high SSD | High | Rejected for the metric; **the right reference for the storage tiering** if MCRIT ever adds embeddings |
| Milvus / Qdrant / Weaviate / Vespa | Vector search platforms | Only via embeddings | Good | Good | Varies | **High** - another distributed system to run | Rejected: large operational cost to answer a different question |
| Annoy | L2 / angular | No | Good, static | Moderate | mmap'd | Low | Rejected: metric, plus rebuild-only index |
| **LSHBloom** (arXiv:2411.04257) | Jaccard, via per-band Bloom filters | Partially | Very fast | Bloom false positives | **Very low** | Low | Rejected as a replacement: a Bloom filter answers *membership*, it cannot enumerate *which* functions matched, and MCRIT must return the matches. Viable only as a negative pre-filter |
| **Two-stage retrieve-then-rerank** | Whatever the exact stage uses | **Yes - orthogonal** | Bounded by shortlist size | Bounded by stage-1 recall, measurable | Low | Low - no new datastore | **Chosen** |
| IDF weighting / document-frequency cutoff | n/a - a traversal policy | Yes | Bounds work by construction | Trades tail recall | None | Low - one config knob | **Chosen**, as stage 1's input |
| WAND / MaxScore early termination | n/a - a traversal policy | Yes | Skips lists that cannot change top-K | Lossless for top-K when bounds are exact | None | Moderate - needs per-list score bounds | **Deferred**: strictly better than a flat cutoff, but needs maintained upper bounds per posting list |
| Sharding by band hash | n/a - a partitioning strategy | Yes | Parallel fan-out, bounded per shard | Lossless | Scales out | High - distributed deployment | **Deferred**: the right answer beyond one machine, and the design below stays compatible with it |

## What the scale literature actually agrees on

The systems that do this at a billion-plus items do not win with a cleverer index alone; they
win by **not scoring most of the corpus**:

- **CEBin** (ISSTA 2024) - large-scale binary code similarity: embedding-based *retrieval* to
  narrow the pool, then pairwise *comparison* on the shortlist only. Reports finding a similar
  function among millions in seconds, orders of magnitude faster than pairwise baselines.
- **Web search / IR** - the same shape for decades: a cheap recall stage over an inverted
  index, then an expensive ranker over the top-K. IDF, stopword elimination and WAND exist
  precisely because posting-list length is Zipfian and the longest lists are the least
  informative.
- **Recommendation** - candidate generation then ranking, for the same reason.

MCRIT's band index is already the inverted index of stage 1. What it lacked was any bound on
how much of it a query traverses, and any bound on how many samples the answer describes.

## Decision

Keep LSH banding. Add the two properties the literature says are load-bearing:

1. **Bound the traversal** - skip band hashes whose posting list is too long to discriminate
   (`STORAGE_BAND_DF_CUTOFF`). A band hash held by a large share of the corpus is a stopword.
2. **Bound the answer** - rank candidate samples cheaply, keep the best N, and run the
   existing exact matching against only those (`MINHASH_MATCHING_SHORTLIST_SIZE`).

Both default to off, so the change is opt-in and an existing deployment is bit-identical until
it opts in. Neither requires a new datastore, a re-index, or a change to what "similar" means -
which is why this was chosen over every option above that is individually more impressive.

## What this does not solve, and what comes next

- **Beyond one machine.** A petabyte corpus is a sharding problem, not an indexing one. Band
  hashes partition cleanly (hash-partition the band collections), and the two-stage design is
  compatible: stage 1 fans out per shard, each returns its local top-N, and the merged
  shortlist feeds stage 2. Not implemented here.
- **WAND over a flat cutoff.** A document-frequency cutoff is a blunt instrument: it discards a
  long posting list entirely, where WAND would skip it only while it cannot change the top-K.
  Adopting WAND needs a maintained score bound per posting list.
- **Signature-level deduplication.** Two functions with byte-identical signatures score
  identically against any query, so scoring one representative per distinct signature is
  *exactly* equivalent - not an approximation. Measured on 257 real Malpedia samples, 185,387
  hashed functions carry only 75,323 distinct signatures (2.46x), and the fitted Heaps' law
  (V(n) = 1412.8 * n^0.7247) puts that at **~24x at a million samples** - i.e. ~96% of pairwise
  scoring there is provably redundant. This is the largest remaining *lossless* win.
