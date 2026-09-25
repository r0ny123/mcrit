import json
import unittest
from unittest.mock import MagicMock

import falcon
import falcon.testing

from mcrit.server.FamilyResource import FamilyResource
from mcrit.server.SampleResource import SampleResource

# what the messages promise: "family_name may be 0-64 alphanumeric chars with single dots, dashes,
# underscores inbetween", "version may be 0-64 printable characters", and the same for component
FAMILY_NAMES_ALLOWED = ["", "x", "7", "ab", "a.b-c_d", "win.citadel", "x" * 64]
FAMILY_NAMES_REFUSED = ["-", "_", ".", "a-", "-a", "a--b", "a._b", "a b", "é", "x" * 65, "ab\n", "\n"]
VALUES_ALLOWED = ["", "1", " ", "1.0-x86", "~" * 64]
VALUES_REFUSED = ["x" * 65, "\t", "é", "1.0\n", "\n"]


def _put(resource, path, body, **ids):
    environ = falcon.testing.create_environ(path=path, method="PUT", body=json.dumps(body), headers={"Content-Type": "application/json"})
    resp = falcon.Response()
    resource.on_put(falcon.Request(environ), resp, **ids)
    return resp


class EditsAcceptWhatTheirMessagesAllow(unittest.TestCase):
    """PUT /samples/<id> and PUT /families/<id> refused "" and one-character values although their
    messages allow 0-64 characters: the family pattern needed a first and a last character, and the
    version and component patterns needed at least one. "" is what a sample submitted without a
    version or component carries, and the name of family 0."""

    def _edit_sample(self, body):
        index = MagicMock()
        return index, _put(SampleResource(index), "/samples/16", body, sample_id=16)

    def _edit_family(self, body):
        index = MagicMock()
        return index, _put(FamilyResource(index), "/families/5", body, family_id=5)

    def test_a_sample_takes_every_value_the_messages_allow(self):
        bodies = [{"family_name": name} for name in FAMILY_NAMES_ALLOWED]
        bodies += [{field: value} for field in ("version", "component") for value in VALUES_ALLOWED]
        for body in bodies:
            with self.subTest(body=body):
                index, resp = self._edit_sample(body)
                self.assertEqual(falcon.HTTP_202, resp.status)
                index.modifySample.assert_called_once()
                self.assertEqual((16, body), index.modifySample.call_args.args)

    def test_a_sample_still_refuses_what_the_messages_rule_out(self):
        bodies = [{"family_name": name} for name in FAMILY_NAMES_REFUSED]
        bodies += [{field: value} for field in ("version", "component") for value in VALUES_REFUSED]
        for body in bodies:
            with self.subTest(body=body):
                index, resp = self._edit_sample(body)
                self.assertEqual(falcon.HTTP_400, resp.status)
                index.modifySample.assert_not_called()

    def test_a_sample_takes_the_empty_values_the_client_sends_as_a_form(self):
        # McritClient.modifySample sends its fields form-encoded, which is how MCRITweb clears a
        # version or component: the empty values arrive as "" and are not dropped
        environ = falcon.testing.create_environ(path="/samples/16", method="PUT", body="version=&component=", headers={"Content-Type": "application/x-www-form-urlencoded"})
        index, resp = MagicMock(), falcon.Response()
        SampleResource(index).on_put(falcon.Request(environ), resp, sample_id=16)
        self.assertEqual(falcon.HTTP_202, resp.status)
        self.assertEqual((16, {"version": "", "component": ""}), index.modifySample.call_args.args)

    def test_a_family_takes_every_name_the_message_allows(self):
        for name in FAMILY_NAMES_ALLOWED:
            with self.subTest(name=name):
                index, resp = self._edit_family({"family_name": name})
                self.assertEqual(falcon.HTTP_202, resp.status)
                self.assertEqual((5, {"family_name": name}), index.modifyFamily.call_args.args)

    def test_a_family_still_refuses_what_the_message_rules_out(self):
        for name in FAMILY_NAMES_REFUSED:
            with self.subTest(name=name):
                index, resp = self._edit_family({"family_name": name})
                self.assertEqual(falcon.HTTP_400, resp.status)
                index.modifyFamily.assert_not_called()
