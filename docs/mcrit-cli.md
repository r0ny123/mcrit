# MCRIT CLI

In this document we describe the different ways of interaction enabled by the MCRIT console client.

## Submit

The `submit` command supports 4 methods of data submission, supported by a number of auxiliary flags.  
Here is its documentation:

```
usage: mcrit client submit [-h] [--mode {file,dir,recursive,malpedia,ida}] [-f FAMILY] [-v VERSION] [-l] [-x] [-o OUTPUT]
                           [-s] [-w] [-t WORKER_TIMEOUT] [--sig-bundles SIG_BUNDLES [SIG_BUNDLES ...]]
                           filepath

positional arguments:
  filepath              Submit the folllowing <filepath>, indicating a (file/dir).

options:
  -h, --help            show this help message and exit
  --mode {file,dir,recursive,malpedia,ida}
                        Submit a single <file> or all files in a <dir>. Use <recursive> submission for a folder
                        structured as ./family_name/version/version/files. Synchronize <malpedia> into MCRIT. Use <ida> for IDA-based FLIRT signature analysis. Default: <file>.
  -f FAMILY, --family FAMILY
                        Set/Override SmdaReport with this family (only in modes: file/dir)
  -v VERSION, --version VERSION
                        Set/Override SmdaReport with this version (only in modes: file/dir)
  -l, --library         Set/Override SmdaReport with the library flag (only in modes: file/dir/recursive, default:
                        False).
  -x, --executables_only
                        Only process files that are parsable PE or ELF files (default: False).
  -o OUTPUT, --output OUTPUT
                        Optionally store SMDA reports in folder OUTPUT.
  -s, --smda            Do not disassemble, instead only submit files that are recognized as SMDA reports (only works
                        with modes: file/dir).
  -w, --worker          Spawn workers to process the submission (only in modes: dir/recursive/malpedia, default:
                        False).
  -t WORKER_TIMEOUT, --worker-timeout WORKER_TIMEOUT
                        Timeout for workers to conclude the submission (default: 300 seconds).
  --sig-bundles SIG_BUNDLES [SIG_BUNDLES ...]
                        List of FLIRT .sig files to apply in IDA mode (default: Hex-Rays standard set). Only used with --mode ida.
```

### File

Submit a single file.  
If the provided path ends with `0x[0-9a-fA-F]{8,16}`, the client will assume that this is a mapped file (no evaluation of PE header) and use the given addr as IMAGEBASE. 
```bash
$ mcrit client submit --mode file ~/malpedia/win.wannacryptor/vt-2017-05-05/0345782378ee7a8b48c296a120625fd439ed8699ae857c4f84befeb56e727366_dump_0x00400000 
 0.906s -> (architecture: intel.32bit, base_addr: 0x00400000): 922 functions
```

### Directory

Submit all files in a directory (no recursion).

```bash
$ mcrit client submit --mode dir ~/malpedia/win.wannacryptor/vt-2017-05-12/
 0.763s -> (architecture: intel.32bit, base_addr: 0x00400000): 926 functions
 0.884s -> (architecture: intel.32bit, base_addr: 0x00400000): 926 functions
 1.378s -> (architecture: intel.32bit, base_addr: 0x00400000): 165 functions
 0.830s -> (architecture: intel.32bit, base_addr: 0x00400000): 926 functions
 ```

 ### Recursive

 Recursively submit all files found in a directory, assume a structure like 
 ```
 ./family_name/version/version/files
 ```
 and use `family_name` and optionally `version` as tags in MCRIT.


 ### Malpedia

Dedicated mode to synchronize all data available in the Malpedia repository.  
If files from Malpedia are already available in MCRIT, they will be skipped on the next execution, making this command suitable to synchronize updated states of Malpedia into MCRIT.  
Only ELF and PE (win.*) families and only files labeled as `_unpacked` or `_dump_0x...`  will be considered and processed.

 ```
 $ mcrit client submit --mode malpedia ~/malpedia
/home/analyst/work/Repositories/malpedia/win.3cx_backdoor/11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03_unpacked
 1.625s -> (architecture: intel.64bit, base_addr: 0x180000000): 717 functions
/home/analyst/work/Repositories/malpedia/win.8t_dropper/2019-01-23/b541e0e29c34800a067b060d9ee18d8d35c75f056f4246b1ce9561a5441d5a0f_unpacked
 0.305s -> (architecture: intel.32bit, base_addr: 0x10000000): 213 functions
[...]
```

### IDA (FLIRT Signature Bulk Analysis)

Submit a single file or all files in a directory using IDA in headless mode. For each sample, IDA will apply the specified FLIRT signature bundles (or the default set), extract all identified function names and addresses, and upload the results to MCRIT in SMDA report format.

```bash
$ mcrit client submit --mode ida --sig-bundles /path/to/flirt1.sig /path/to/flirt2.sig /samples_dir
[IDA MODE] Placeholder: will run IDA headless for each sample, apply FLIRT signatures, and upload results.
```

- The `--sig-bundles` option is optional; if omitted, the default Hex-Rays signature set will be used.
- Progress and errors will be reported for each sample.

## Export

This command can be used to export samples into MCRIT-compatible files, e.g.:

```bash
usage: mcrit client export [-h] [--sample_ids SAMPLE_IDS] filepath

$ mcrit client export --sample_ids 0 sample_0.mcrit
wrote export to sample_0.mcrit.

$ head sample_0.mcrit 
{
 "content": {
  "is_compressed": true,
  "num_families": 1,
  "num_samples": 1,
  "num_functions": 214
 },
 "config": {
  "version": "0.19.0",
  "shingler": "7ae53d3b2514730a4d48f993a3e4cd6c6d4a5ca26f93bbed98e0f498295552de",
[...]
```

## Import

This command can be used to import previously exported sample(s), e.g.:

```bash
usage: mcrit client import [-h] filepath

$ mcrit client import sample_0.mcrit               
{'num_samples_imported': 0, 'num_samples_skipped': 1, 'num_functions_imported': 0, 'num_functions_skipped': 214, 'num_families_imported': 0, 'num_families_skipped': 1}

```

## Search

This command can be used to search across families, samples, and functions, e.g.:

```bash
usage: mcrit client search [-h] search_term

$ mcrit client search wanna                                               
Family Search Results
Famliy 2 (win.wannacry): 
********************
Sample Search Results
Sample 1 (intel, 32 bit) - ca29de1dc8817868c93e54b09f557fe14e40083c0955294df5bd91f52ba469c8_unpacked (win.wannacry): 
Sample 2 (intel, 32 bit) - 3e6de9e2baacf930949647c399818e7a2caea2626df6a468407854aaa515eed9 (win.wannacry): 
********************
```

## Queue

This command can be used to get a view on all queued jobs and their processing status, e.g.:

```bash
$ mcrit client queue
64243b27f3876416bffad86e 64243b28cbc77c2df4d8d79f | 2023-03-29T13:20:39.065Z 2023-03-29T13:20:39.114Z 2023-03-29T13:20:40.593Z | updateMinHashesForSample(2) - 1
64131888fbb4d9d4a029164d 6413188c15e4f20d519b35ba | 2023-03-16T13:24:24.707Z 2023-03-16T13:24:24.755Z 2023-03-16T13:24:28.366Z | addBinarySample(None, ca29de1dc8817868c93e54b09f557fe14e40083c0955294df5bd91f52ba469c8_unpacked, win.wannacry, , False, 0, 32) - 1
641316eefbb4d9d4a029164a 641316f115e4f20d519b322b | 2023-03-16T13:17:34.834Z 2023-03-16T13:17:34.859Z 2023-03-16T13:17:37.238Z | addBinarySample(None, 766d7d591b9ec1204518723a1e5940fd6ac777f606ed64e731fd91b0b4c3d9fc_dump_0x10000000, win.contopee, , True, 268435456, 32) - 1
```