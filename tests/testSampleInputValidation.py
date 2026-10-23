"""Binary sample submission refuses query values it used to misread, before scheduling a job."""

import json
import unittest
from unittest.mock import MagicMock

import falcon
import falcon.testing

from mcrit.server.SampleResource import SampleResource


def request(method, path, body=b"", query_string=""):
    return falcon.Request(falcon.testing.create_environ(path=path, method=method, body=body, query_string=query_string))


class SampleInputValidationTest(unittest.TestCase):
    def setUp(self):
        self.index = MagicMock()
        self.index.getSampleBySha256.return_value = None
        self.index.addBinarySample.return_value = "job-id"
        self.resource = SampleResource(self.index)

    def submit(self, query_string):
        response = falcon.Response()
        self.resource.on_post_submit_binary(request("POST", "/samples/binary", b"MZ", query_string), response)
        return response

    def test_metadata_is_decoded_and_forwarded(self):
        response = self.submit("filename=dir%2Ffile%20%28one%29.exe&family=Emotet%20Loader&version=v1.2&is_dump=true&base_addr=0x1000&bitness=64")
        self.assertEqual(falcon.HTTP_202, response.status)
        self.assertEqual("job-id", json.loads(response.data)["data"])
        args = self.index.addBinarySample.call_args.args
        self.assertEqual((b"MZ", "dir/file (one).exe", "Emotet Loader", "v1.2", True, 0x1000, 64), args)

    def test_absent_and_blank_values_fall_back_to_the_defaults(self):
        for query_string in ("", "is_dump=&base_addr=&bitness="):
            with self.subTest(query_string=query_string):
                response = self.submit(query_string)
                self.assertEqual(falcon.HTTP_202, response.status)
                self.assertEqual((b"MZ", None, None, None, False, 0, 32), self.index.addBinarySample.call_args.args)

    def test_is_dump_spellings_are_read_as_before(self):
        for value, expected in (("True", True), ("true", True), ("1", True), ("False", False), ("false", False), ("0", False)):
            with self.subTest(value=value):
                self.assertEqual(falcon.HTTP_202, self.submit(f"is_dump={value}").status)
                self.assertIs(expected, self.index.addBinarySample.call_args.args[4])

    def test_bitness_32_and_64_are_read_as_before(self):
        for value in (32, 64):
            with self.subTest(value=value):
                self.assertEqual(falcon.HTTP_202, self.submit(f"bitness={value}").status)
                self.assertEqual(value, self.index.addBinarySample.call_args.args[6])

    def test_unreadable_values_are_refused_and_logged_without_scheduling_a_job(self):
        for query_string in (
            "is_dump=yes",
            "is_dump=maybe",
            "is_dump=TRUE",
            "bitness=16",
            "bitness=128",
            "bitness=abc",
            "base_addr=invalid",
            "base_addr=-1000",
            "base_addr=10000000000000000",
        ):
            with self.subTest(query_string=query_string):
                self.index.addBinarySample.reset_mock()
                self.index._storage.dbLogEvent.reset_mock()
                response = self.submit(query_string)
                self.assertEqual(falcon.HTTP_400, response.status)
                self.assertEqual("failed", json.loads(response.data)["status"])
                self.index.addBinarySample.assert_not_called()
                self.index.getSampleBySha256.assert_not_called()
                self.index._storage.dbLogEvent.assert_called_once()


if __name__ == "__main__":
    unittest.main()
