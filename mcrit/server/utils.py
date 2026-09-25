import logging
from timeit import default_timer as timer

from bson import json_util

LOGGER = logging.getLogger(__name__)


def get_username(req):
    """The user a request was made for, as MCRITweb and McritClient send it, or None."""
    return req.get_header("username", default=None)


def db_log_msg(index, req, message, level=None):
    username = get_username(req) or "anonymous"
    if level is None:
        LOGGER.info(f"{username} - {message}")
    index._storage.dbLogEvent(message, username=username)
    return


def getMatchingParams(req_params, config=None):
    """The matching options of a request, as keyword arguments for the matching jobs.

    Given the server's config, the two-stage knobs a request leaves out are filled in with the
    configured values (#217): they change which matches are reported, and a job's cache key is its
    arguments, so without this a result computed under one setting would be served for another.
    """
    parameters = {}
    for key, value in req_params.items():
        try:
            if key == "pichash_size":
                pichash_size = int(value)
                pichash_size = max(0, pichash_size)
                parameters["pichash_size"] = pichash_size
                # self.index.updatePicHashSize(pichash_size)
            if key == "minhash_score":
                minhash_score = int(value)
                minhash_score = max(0, min(100, minhash_score))
                parameters["minhash_threshold"] = minhash_score
            if key == "force_recalculation":
                if value.lower() == "true":
                    parameters["force_recalculation"] = True
            if key == "sample_group_only":
                if value.lower() == "true":
                    parameters["sample_group_only"] = True
            if key == "band_matches_required":
                band_matches_required = int(value)
                band_matches_required = max(0, band_matches_required)
                parameters["band_matches_required"] = band_matches_required
            if key in ("shortlist_size", "band_df_cutoff"):
                # 0 switches the stage off, as the configuration knobs do; a job's arguments are
                # stored in MongoDB, whose integers end at 2**63 - 1
                number = int(value)
                if number >= 2**63:
                    raise ValueError(f"{key} out of range")
                parameters[key] = max(0, number)
        except (AttributeError, TypeError, ValueError):
            LOGGER.warning(f"Failed to handle request parameter: {key}: {value}")
    if config is not None:
        parameters.setdefault("shortlist_size", getattr(config.MINHASH_CONFIG, "MINHASH_MATCHING_SHORTLIST_SIZE", 0))
        parameters.setdefault("band_df_cutoff", getattr(config.STORAGE_CONFIG, "STORAGE_BAND_DF_CUTOFF", 0))
    return parameters


def getUniqueBlocksParams(req_params):
    parameters = {}
    for key, value in req_params.items():
        try:
            if key == "covers_required":
                # k of the k-of-n cover: every sample must be reached by this many selected blocks
                parameters["covers_required"] = max(1, int(value))
            if key == "min_instructions":
                # blocks shorter than this are dropped before the cover is chosen
                parameters["min_instructions"] = max(0, int(value))
        except (AttributeError, TypeError, ValueError):
            LOGGER.warning(f"Failed to handle request parameter: {key}: {value}")
    return parameters


def jsonify(content, debug_print=False):
    if debug_print:
        print(content)
        print(json_util.dumps(content).encode("utf-8"))
    return json_util.dumps(content).encode("utf-8")


def timing(func):
    def wrapper(*args, **kwargs):
        start = timer()
        func(*args, **kwargs)
        end = timer()
        LOGGER.info("  *** this took: %s sec" % (end - start))

    return wrapper
