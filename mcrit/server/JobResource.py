import datetime
import re
from typing import Optional

import falcon

from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.libs.utility import parse_sample_id
from mcrit.queue.LocalQueue import Job
from mcrit.server.utils import db_log_msg, jsonify, timing

# TODO these should also return status and data in their json response


# the parameters that select jobs, shared by GET /jobs and GET /jobs/count, and those only the
# listing reads on top of them
_SELECTION_PARAMETERS = ("method", "state", "filter", "username", "sample_ids", "job_ids")
_PAGING_PARAMETERS = ("start", "limit", "ascending")


def _split_csv(value):
    """The entries of a comma-separated parameter; blank entries, as a trailing comma leaves, are no entries."""
    return [item.strip() for item in value.split(",") if item.strip()]


def _name_invalid(entries, shown=10):
    """The rejected entries for a 400 message, as many as are useful to read."""
    named = ", ".join(repr(entry[:40]) for entry in entries[:shown])
    if len(entries) > shown:
        named += f" and {len(entries) - shown} more"
    return named


class JobResource:
    def __init__(self, index: MinHashIndex):
        self.index = index

    def _reject(self, req, resp, responder, message, log_message=None):
        resp.status = falcon.HTTP_400
        resp.data = jsonify({"status": "failed", "data": {"message": message}})
        db_log_msg(self.index, req, f"JobResource.{responder} - failed - {log_message or message}")

    def _selection(self, req, resp, responder, other_parameters=()) -> Optional[dict]:
        """The parameters that select jobs, shared by the listing and its count, or None once a 400 is answered.

        Every parameter is taken once: falcon hands a repeated one over as a list, which none of them
        is parsed as. sample_ids takes integers and requires method, job_ids takes ObjectIds - the 24
        hex characters /jobs/{job_id} asks for, here checked over the whole entry. An entry that does
        not parse is named in the 400 rather than dropped, since dropping it would answer for a
        different selection than the one asked for.
        """
        repeated = [name for name in (*_SELECTION_PARAMETERS, *other_parameters) if isinstance(req.params.get(name), list)]
        if repeated:
            self._reject(req, resp, responder, f"Query parameters may be given only once: {', '.join(repeated)}.")
            return None
        selection = {
            "method": req.params.get("method", None),
            "state": req.params.get("state", None),
            "filter": req.params.get("filter", None),
            "username": req.params.get("username", None),
            "sample_ids": None,
            "job_ids": None,
        }
        if "sample_ids" in req.params:
            if selection["method"] is None:
                self._reject(req, resp, responder, "sample_ids requires method to be set as well.", "sample_ids without method.")
                return None
            entries = _split_csv(req.params["sample_ids"])
            invalid = [entry for entry in entries if parse_sample_id(entry) is None]
            if invalid:
                self._reject(req, resp, responder, f"Invalid sample_ids, which must be integers: {_name_invalid(invalid)}.", "invalid sample_ids.")
                return None
            selection["sample_ids"] = [parse_sample_id(entry) for entry in entries]
        if "job_ids" in req.params:
            entries = _split_csv(req.params["job_ids"])
            invalid = [entry for entry in entries if re.fullmatch("[0-9a-fA-F]{24}", entry) is None]
            if invalid:
                self._reject(req, resp, responder, f"Invalid job_ids, which must be 24 hex characters: {_name_invalid(invalid)}.", "invalid job_ids.")
                return None
            # lower case, as str(ObjectId) renders an id; MongoQueue's ObjectId() takes either case
            selection["job_ids"] = [entry.lower() for entry in entries]
        return selection

    @timing
    def on_get_count(self, req, resp):
        """How many jobs match the same selection ``GET /jobs`` takes, without paging through them. Answers ``count``."""
        selection = self._selection(req, resp, "on_get_count")
        if selection is None:
            return
        count = self.index.getQueueCount(**selection)
        resp.data = jsonify({"status": "successful", "data": {"count": count}})
        db_log_msg(self.index, req, "JobResource.on_get_count - success.")

    @timing
    def on_get_collection(self, req, resp):
        selection = self._selection(req, resp, "on_get_collection", other_parameters=_PAGING_PARAMETERS)
        if selection is None:
            return
        # parse optional request parameters
        ascending = False
        if "ascending" in req.params:
            ascending = req.params["ascending"].lower().strip() == "true"
        start_job_id = 0
        if "start" in req.params:
            try:
                start_job_id = int(req.params["start"])
            except ValueError:
                pass
        limit_job_count = 0
        if "limit" in req.params:
            try:
                limit_job_count = int(req.params["limit"])
            except ValueError:
                pass
        queue_data = self.index.getQueueData(start_index=start_job_id, limit=limit_job_count, ascending=ascending, **selection)
        resp.data = jsonify({"status": "successful", "data": queue_data})
        db_log_msg(self.index, req, "JobResource.on_get_collection - success.")

    @timing
    def on_get_stats(self, req, resp):
        query_with_refresh = False
        if "with_refresh" in req.params:
            query_with_refresh = req.params["with_refresh"].lower().strip() == "true"
        queue_data = self.index.getQueueStats(refresh=query_with_refresh)
        resp.data = jsonify({"status": "successful", "data": queue_data})
        db_log_msg(self.index, req, "JobResource.on_get_stats - success.")

    @timing
    def on_delete_collection(self, req, resp):
        # parse optional request parameters, to be used as an "AND" query
        method_filter = None
        if "method" in req.params:
            method_filter = req.params["method"]
        created_before = None
        if "created_before" in req.params:
            try:
                if len(req.params["created_before"]) == 10:
                    created_before = datetime.datetime.strptime(req.params["created_before"], "%Y-%m-%d")
                else:
                    created_before = datetime.datetime.strptime(req.params["created_before"], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                pass
        finished_before = None
        if "finished_before" in req.params:
            try:
                if len(req.params["finished_before"]) == 10:
                    finished_before = datetime.datetime.strptime(req.params["finished_before"], "%Y-%m-%d")
                else:
                    finished_before = datetime.datetime.strptime(req.params["finished_before"], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                pass
        # newest first
        result = self.index.deleteQueueData(method=method_filter, created_before=created_before, finished_before=finished_before)
        resp.data = jsonify({"status": "successful", "data": {"num_deleted": result}})
        db_log_msg(self.index, req, "JobResource.on_delete_collection - success.")

    @timing
    def on_get(self, req, resp, job_id=None):
        # validate that we only allow hexstrings with 24 chars
        if job_id is None or not re.match("[a-fA-F0-9]{24}", job_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify({"status": "failed", "data": {"message": "Valid JobIDs are hexstrings with 24 characters."}})
            db_log_msg(self.index, req, "JobResource.on_get - failed - invalid job_id.")
            return
        data = self.index.getJobData(job_id)
        # TODO throw 404 if job_id is unknown
        # resp.status = falcon.HTTP_404
        resp.data = jsonify({"status": "successful", "data": data})
        db_log_msg(self.index, req, "JobResource.on_get - success.")

    @timing
    def on_delete(self, req, resp, job_id=None):
        # validate that we only allow hexstrings with 24 chars
        if job_id is None or not re.match("[a-fA-F0-9]{24}", job_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify({"status": "failed", "data": {"message": "Valid JobIDs are hexstrings with 24 characters."}})
            db_log_msg(self.index, req, "JobResource.on_delete - failed - invalid job_id.")
            return
        result = self.index.deleteJob(job_id)
        # TODO throw 404 if job_id is unknown
        # resp.status = falcon.HTTP_404
        resp.data = jsonify({"status": "successful", "data": {"num_deleted": result}})
        db_log_msg(self.index, req, "JobResource.on_delete - success.")

    @staticmethod
    def _wants_compact(req):
        return "compact" in req.params and req.params["compact"].lower().strip() == "true"

    def _respond_with_result(self, resp, job_data, compact, result_bytes, parse_result):
        """Answer a stored result inside the success envelope.

        The result is stored as JSON, so unless the caller wants the compact form (which
        drops the function matches and therefore needs the parsed dict) the stored bytes go
        into the envelope as they are, instead of being parsed and serialised again - which
        cost more than reading the report for an 8 MB result (#152).
        """
        if compact:
            data = parse_result()
            if job_data and data is not None:
                job_info = Job(job_data, None)
                if job_info.is_matching_job or job_info.is_query_job:
                    data["matches"].pop("functions")
            resp.data = jsonify({"status": "successful", "data": data})
            return
        if result_bytes is None:
            resp.data = jsonify({"status": "successful", "data": None})
            return
        resp.data = b'{"status": "successful", "data": ' + result_bytes + b"}"

    @timing
    def on_get_results(self, req, resp, result_id=None):
        # validate that we only allow hexstrings with 24 chars
        if result_id is None or not re.match("[a-fA-F0-9]{24}", result_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify({"status": "failed", "data": {"message": "Valid ResultIDs are hexstrings with 24 characters."}})
            db_log_msg(self.index, req, "JobResource.on_get_results - failed - invalid result_id.")
            return
        job_id = self.index.getJobIdForResult(result_id)
        job_data = self.index.getJobData(job_id)
        compact = self._wants_compact(req)
        # TODO throw 404 if job_id is unknown
        # resp.status = falcon.HTTP_404
        self._respond_with_result(resp, job_data, compact, None if compact else self.index.getResultBytes(result_id), lambda: self.index.getResult(result_id))
        db_log_msg(self.index, req, "JobResource.on_get_results - success.")

    @timing
    def on_get_job_result(self, req, resp, job_id=None):
        # validate that we only allow hexstrings with 24 chars
        if job_id is None or not re.match("[a-fA-F0-9]{24}", job_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify({"status": "failed", "data": {"message": "Valid JobIDs are hexstrings with 24 characters."}})
            db_log_msg(self.index, req, "JobResource.on_get_job_result - failed - invalid job_id.")
            return
        job_data = self.index.getJobData(job_id)
        compact = self._wants_compact(req)
        # TODO throw 404 if job_id is unknown
        # resp.status = falcon.HTTP_404
        self._respond_with_result(resp, job_data, compact, None if compact else self.index.getResultBytesForJob(job_id), lambda: self.index.getResultForJob(job_id))
        db_log_msg(self.index, req, "JobResource.on_get_job_result - success.")

    @timing
    def on_get_result_job(self, req, resp, result_id=None):
        # validate that we only allow hexstrings with 24 chars
        if result_id is None or not re.match("[a-fA-F0-9]{24}", result_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify({"status": "failed", "data": {"message": "Valid ResultIDs are hexstrings with 24 characters."}})
            db_log_msg(self.index, req, "JobResource.on_get_job_result - failed - invalid result_id.")
            return
        job_id = self.index.getJobIdForResult(result_id)
        data = self.index.getJobData(job_id)
        # TODO throw 404 if job_id is unknown
        # resp.status = falcon.HTTP_404
        resp.data = jsonify({"status": "successful", "data": data})
        db_log_msg(self.index, req, "JobResource.on_get_result_job - success.")
