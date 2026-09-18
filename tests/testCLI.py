#!/usr/bin/python

import logging
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from mcrit.client.McritConsole import McritConsole, get_primary_smda_meta_data, is_smda_report

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class TestCLI(unittest.TestCase):
    """Run a full example on a memory dump"""

    def testIsSmdaReport(self):
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path_1 = os.sep.join([PROJECT_ROOT, "tests", "example_report_meta.smda"])
        wrong_example_path = os.sep.join([PROJECT_ROOT, "tests", "example_matching_report.json"])
        self.assertTrue(is_smda_report(example_file_path_1))
        self.assertFalse(is_smda_report(wrong_example_path))

    def testGetPrimaryMeta(self):
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path_1 = os.sep.join([PROJECT_ROOT, "tests", "example_report_meta.smda"])
        smda_meta = get_primary_smda_meta_data(example_file_path_1)
        self.assertIsNotNone(smda_meta)
        self.assertEqual(smda_meta["sha256"], "ae38ff0778fb8dfa1deb17301a15165934312648d232d167cd0c0034c24689e1")
        self.assertEqual(smda_meta["filename"], "example_filename")
        self.assertEqual(smda_meta["family"], "example_family")
        self.assertEqual(smda_meta["version"], "example_version")

    def testRecursiveSubmitsFiles(self):
        console = McritConsole()
        console.client = MagicMock()
        console.client.getSamples.return_value = {}
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_dir = os.sep.join([tmp_dir, "some_family", "1.0"])
            os.makedirs(sample_dir)
            sample_path = os.sep.join([sample_dir, "some_sample"])
            with open(sample_path, "wb") as fout:
                fout.write(b"MZ\x90\x00")
            args = console.parser.parse_args(["client", "submit", "--mode", "recursive", tmp_dir])
            args.filepath = tmp_dir
            with patch("mcrit.client.McritConsole.getSmdaReportFromFilepath") as mock_get_report:
                mock_get_report.return_value = MagicMock(family="", version="")
                console._handle_submit_recursive(args)
            mock_get_report.assert_called_once_with(args, sample_path)
            console.client.addReport.assert_called_once()


if __name__ == "__main__":
    unittest.main()
