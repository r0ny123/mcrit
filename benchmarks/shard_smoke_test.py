import json, sys, time
from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.storage.StorageFactory import StorageFactory
from smda.common.SmdaReport import SmdaReport

def main():
    use_pool = "--pool" in sys.argv
    cfg = McritConfig()
    cfg.STORAGE_CONFIG = StorageConfig(
        STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB,
        STORAGE_SERVER="127.0.0.1", STORAGE_PORT="27117",
        STORAGE_MONGODB_DBNAME="sharded", STORAGE_BAND_BUCKET_SIZE=100000)
    cfg.MINHASH_CONFIG = MinHashConfig()
    cfg.MINHASH_CONFIG.MINHASH_POOL_INDEXING = use_pool
    cfg.SHINGLER_CONFIG = ShinglerConfig()
    cfg.QUEUE_CONFIG = QueueConfig()
    cfg.QUEUE_CONFIG.QUEUE_MONGODB_DBNAME = "sharded_queue"
    cfg.QUEUE_CONFIG.QUEUE_METHOD = QueueFactory.QUEUE_METHOD_FAKE
    index = MinHashIndex(config=cfg)
    # deliberately NOT clearStorage(): it drops the collections, and dropping a sharded collection
    # discards its shard key with it, silently leaving the database unsharded
    t = time.time()
    for path in ("tests/example_report.smda", "tests/example_report_2.smda"):
        index.addReport(SmdaReport.fromDict(json.load(open(path))))
    s = index.getStatus()["status"]
    print("RESULT pool=%s samples=%d functions=%d in %.1fs" % (use_pool, s["num_samples"], s["num_functions"], time.time() - t))

if __name__ == "__main__":
    main()
