#!/usr/bin/python

import argparse
import hashlib
import io
import logging
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, call, patch

from mcrit.client.McritConsole import McritConsole, get_base_addr, get_primary_smda_meta_data, is_smda_report

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)

SHA256 = "a" * 64


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


class TestSubmitModes(unittest.TestCase):
    def testMalpediaFilenames(self):
        # #280: every dump was skipped, as the pattern lacked the underscore before "dump"
        console = McritConsole.__new__(McritConsole)
        for suffix in ("_unpacked", "_dump_0x00400000", "_dump7_0x00400000", "_dump10_0x0000000140000000", "_dump7_0x00350000_loader"):
            with self.subTest(suffix=suffix):
                self.assertTrue(console._isMalpediaFilename(SHA256 + suffix))
        for filename in (SHA256, SHA256 + "dump7_0x00400000", SHA256 + "_packed", SHA256 + "_dump_0x0040", SHA256 + "_dump_0x00400000000000000", "B" * 64 + "_unpacked"):
            with self.subTest(filename=filename):
                self.assertFalse(console._isMalpediaFilename(filename))

    def testBaseAddressOfADump(self):
        self.assertEqual(0x400000, get_base_addr(SHA256 + "_dump7_0x00400000"))
        self.assertEqual(0x350000, get_base_addr(SHA256 + "_dump7_0x00350000_loader"))
        self.assertEqual(0x140000000, get_base_addr(SHA256 + "_dump_0x0000000140000000"))
        self.assertEqual(0x400000, get_base_addr(SHA256 + "_dump7_0x00400000_loader_x64.bin"))
        self.assertEqual(0x400000, get_base_addr(os.path.join("malpedia", "win.family", SHA256 + "_dump7_0x00400000_loader")))
        # only a Malpedia dump name may go on after its address; other files read as before
        self.assertIsNone(get_base_addr("sample_0x00400000_copy"))
        self.assertIsNone(get_base_addr("sample_dump_0x00400000_loader"))
        self.assertIsNone(get_base_addr(SHA256 + "_unpacked"))

    def testRecursiveSubmitsEveryFile(self):
        # #281: a leftover continue made --mode recursive print every file and submit none
        console = McritConsole.__new__(McritConsole)
        console.client = MagicMock()
        console.client.getSamples.return_value = {}
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "win.family", "1.0"))
            for name in ("a.bin", "b.bin"):
                with open(os.path.join(root, "win.family", "1.0", name), "wb") as fout:
                    fout.write(name.encode())
            with open(os.path.join(root, "c.bin"), "wb") as fout:
                fout.write(b"c")
            # _handle_submit makes the path absolute before dispatching
            with patch("mcrit.client.McritConsole.getSmdaReportFromFilepath", side_effect=lambda args, filepath: MagicMock()):
                console._handle_submit_recursive(argparse.Namespace(filepath=os.path.abspath(root), worker=False))
        reports = [call.args[0] for call in console.client.addReport.call_args_list]
        self.assertEqual(3, len(reports))
        # a file in the root itself has no family folder
        self.assertEqual({("win.family", "1.0"), ("", "")}, {(report.family, report.version) for report in reports})


def writeFile(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fout:
        fout.write(content)


def consoleWithSamples(*sample_entries):
    console = McritConsole.__new__(McritConsole)
    console.client = MagicMock()
    console.client.getSamples.return_value = {entry.sample_id: entry for entry in sample_entries}
    console.client.getSampleBySha256.side_effect = lambda sha256: next((entry for entry in sample_entries if entry.sha256 == sha256), None)
    return console


def sampleEntry(sample_id, content, family, version):
    return MagicMock(sample_id=sample_id, sha256=hashlib.sha256(content).hexdigest(), family=family, version=version, is_library=False)


class TestSubmitConsistency(unittest.TestCase):
    def testDirModeNamesTheSkippedFile(self):
        with tempfile.TemporaryDirectory() as root:
            filepath = os.path.join(root, "a.bin")
            writeFile(filepath, b"a")
            console = consoleWithSamples(sampleEntry(7, b"a", "family", "1.0"))
            output = io.StringIO()
            with redirect_stdout(output):
                console._handle_submit_dir(argparse.Namespace(filepath=root, worker=False, smda=False, force_update=False))
        # it named the folder given, not the file
        self.assertIn(f"SKIPPING: {filepath} - already in MCRIT.", output.getvalue())

    def testEveryModeSkipsAReportWithoutFunctions(self):
        # dir mode already did; file, recursive and malpedia mode added an empty sample
        with tempfile.TemporaryDirectory() as tmp:
            malpedia_root = os.path.join(tmp, "malpedia")
            writeFile(os.path.join(malpedia_root, "malpedia.bib"), b"")
            empty_path = os.path.join(malpedia_root, "win.family", "1.0", SHA256 + "_unpacked")
            full_path = os.path.join(malpedia_root, "win.family", "1.0", "b" * 64 + "_unpacked")
            writeFile(empty_path, b"empty")
            writeFile(full_path, b"full")
            # SMDA finds no functions in the one file and some in the other
            reports = {empty_path: MagicMock(xcfg={}), full_path: MagicMock(xcfg={0x401000: MagicMock()})}
            arguments = {
                "file": argparse.Namespace(filepath=empty_path, force_update=False),
                "dir": argparse.Namespace(filepath=os.path.dirname(empty_path), worker=False, smda=False, force_update=False),
                # the family folder, as the Malpedia root also holds malpedia.bib
                "recursive": argparse.Namespace(filepath=os.path.join(malpedia_root, "win.family"), worker=False, force_update=False),
                "malpedia": argparse.Namespace(filepath=malpedia_root, worker=False),
            }
            for mode, args in arguments.items():
                console = consoleWithSamples()
                output = io.StringIO()
                with (
                    self.subTest(mode=mode),
                    redirect_stdout(output),
                    patch("mcrit.client.McritConsole.getSmdaReportFromFilepath", side_effect=lambda args, filepath: reports[filepath]),
                ):
                    getattr(console, f"_handle_submit_{mode}")(args)
                    added = [call.args[0] for call in console.client.addReport.call_args_list]
                    self.assertNotIn(reports[empty_path], added)
                    self.assertIn(f"SKIPPING: {empty_path} - SMDA found no functions.", output.getvalue())
                    # file mode was only given the empty one
                    self.assertEqual([] if mode == "file" else [reports[full_path]], added)

    def testRecursiveModeForceUpdatesFromTheFolders(self):
        with tempfile.TemporaryDirectory() as root:
            writeFile(os.path.join(root, "win.family", "1.0", "a.bin"), b"a")
            writeFile(os.path.join(root, "b.bin"), b"b")
            writeFile(os.path.join(root, "win.other", "c.bin"), b"c")
            known = (sampleEntry(7, b"a", "win.old", "0.1"), sampleEntry(8, b"b", "win.kept", "2.0"), sampleEntry(9, b"c", "win.wrong", "3.0"))
            # what no folder names, MCRIT keeps: both for b.bin in the root, the version for c.bin
            expected = {
                (False, False): [],
                (True, False): [call(7, family_name="win.family", version="1.0", is_library=False), call(9, family_name="win.other", version="3.0", is_library=False)],
                (True, True): [
                    call(7, family_name="win.family", version="1.0", is_library=True),
                    call(8, family_name="win.kept", version="2.0", is_library=True),
                    call(9, family_name="win.other", version="3.0", is_library=True),
                ],
            }
            for (force_update, library), calls in expected.items():
                console = consoleWithSamples(*known)
                output = io.StringIO()
                args = argparse.Namespace(filepath=root, worker=False, force_update=force_update, family=None, version=None, library=library)
                with self.subTest(force_update=force_update, library=library), redirect_stdout(output):
                    console._handle_submit_recursive(args)
                    console.client.addReport.assert_not_called()
                    self.assertCountEqual(calls, console.client.modifySample.call_args_list)
                    if not force_update:
                        self.assertEqual(3, output.getvalue().count("- already in MCRIT."))


if __name__ == "__main__":
    unittest.main()
