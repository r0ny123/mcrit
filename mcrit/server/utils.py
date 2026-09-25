import logging
from timeit import default_timer as timer

import falcon
from bson import json_util

from mcrit.matchers.MatcherInterface import shortlistUnavailableReason

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


class MatchingParameterError(ValueError):
    """A matching option set to a value no job can run with; the resource answers it with a 400."""


# a job's arguments are stored in MongoDB, whose integers end here
_MATCHING_KNOB_MAX = 2**63 - 1


def _parseJobKnob(key, value, config):
    """shortlist_size or band_df_cutoff as an int, refusing what the job could not apply (#217).

    Refused rather than ignored, unlike the older options: an ignored value is replaced by the
    configured one, so the caller would get a result computed under a setting they did not ask for,
    with nothing in the response to say so.
    """
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise MatchingParameterError(f"{key} must be an integer, not {value!r}.") from None
    if number < 0 or number > _MATCHING_KNOB_MAX:
        raise MatchingParameterError(f"{key} must be an integer from 0 (off) to {_MATCHING_KNOB_MAX}.")
    bucket_size = getattr(getattr(config, "STORAGE_CONFIG", None), "STORAGE_BAND_BUCKET_SIZE", 0) or 0
    if key == "band_df_cutoff" and bucket_size and number > bucket_size:
        # only bucket 0 carries df, so a spilled hash's df has to be rejectable by the cutoff; the
        # storage refuses such a configured cutoff at startup for the same reason (#196)
        raise MatchingParameterError(f"band_df_cutoff must not exceed STORAGE_BAND_BUCKET_SIZE ({bucket_size}).")
    return number


def getMatchingParams(req_params, config=None, storage=None, with_shortlist=True):
    """The matching options of a request, as keyword arguments for the matching jobs.

    Given the server's config, every option that changes which matches are reported and that the
    request leaves out is filled in with the value the job will run with (#217). A job is reused for
    any later request with the same arguments, so an option left out would key the job on its
    absence rather than on its value, and a result computed under an old configuration would keep
    being served after the configuration changed.

    `with_shortlist=False` is for matches restricted to the samples they name (one against another,
    or within a group): no shortlist applies to them, and none goes into their jobs' arguments.
    Given the storage, a shortlist it cannot apply right now is marked as such in the arguments, so
    the fallback result is kept apart from the shortlisted one.

    Raises MatchingParameterError for an unusable shortlist_size or band_df_cutoff.
    """
    parameters = {}
    for key, value in req_params.items():
        if key in ("shortlist_size", "band_df_cutoff"):
            parameters[key] = _parseJobKnob(key, value, config)
            continue
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
        except (AttributeError, TypeError, ValueError):
            LOGGER.warning(f"Failed to handle request parameter: {key}: {value}")
    if not with_shortlist or parameters.get("sample_group_only"):
        parameters.pop("shortlist_size", None)
    if config is not None:
        parameters.setdefault("minhash_threshold", config.MINHASH_CONFIG.MINHASH_MATCHING_THRESHOLD)
        parameters.setdefault("pichash_size", config.MINHASH_CONFIG.PICHASH_SIZE)
        parameters.setdefault("band_matches_required", config.MINHASH_CONFIG.BAND_MATCHES_REQUIRED)
        parameters.setdefault("band_df_cutoff", getattr(config.STORAGE_CONFIG, "STORAGE_BAND_DF_CUTOFF", 0))
        if with_shortlist and not parameters.get("sample_group_only"):
            parameters.setdefault("shortlist_size", getattr(config.MINHASH_CONFIG, "MINHASH_MATCHING_SHORTLIST_SIZE", 0))
    shortlist_size = parameters.get("shortlist_size")
    if storage is not None and isinstance(shortlist_size, int) and shortlist_size > 0:
        reason = shortlistUnavailableReason(storage)
        if reason is not None:
            parameters["shortlist_unavailable"] = reason
    return parameters


def readMatchingParams(index, req, resp, handler, with_shortlist=True):
    """getMatchingParams for a resource: the parameters, or None after answering a 400 for them."""
    try:
        # the storage directly, as db_log_msg reads it: getStorage() would also run the cleanup
        # scheduling callback on every request
        return getMatchingParams(req.params, index.config, storage=index._storage, with_shortlist=with_shortlist)
    except MatchingParameterError as error:
        resp.status = falcon.HTTP_400
        resp.data = jsonify({"status": "failed", "data": {"message": str(error)}})
        db_log_msg(index, req, f"{handler} - failed - {error}")
        return None


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
