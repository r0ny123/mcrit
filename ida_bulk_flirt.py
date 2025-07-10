#!/usr/bin/env python3
"""
ida_bulk_flirt.py

Usage (to be run by IDA in headless mode):

    ida64 -A -S"ida_bulk_flirt.py --input <binary> --output <report.smda> [--sig-bundles sig1.sig sig2.sig ...]" <binary>

- Applies FLIRT signature bundles to the loaded binary
- Extracts all function names and addresses
- Outputs a SMDA-style JSON report to the specified output file

Arguments:
    --input <binary>         Path to the input binary (required)
    --output <report.smda>   Path to write the SMDA-style report (required)
    --sig-bundles <sig ...>  List of FLIRT .sig files to apply (optional)

Requires IDA 9.0+ and modern IDAPython API.
"""
import sys
import os
import json
import argparse
import traceback

try:
    import idc
    import idaapi
    import ida_funcs
    import ida_nalt
except ImportError:
    print("[ERROR] This script must be run inside IDA Pro with IDAPython.")
    sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description="Bulk FLIRT signature application and function extraction for MCRIT.")
    parser.add_argument('--input', required=True, help='Input binary path (for reference only, IDA loads it)')
    parser.add_argument('--output', required=True, help='Output SMDA-style report path')
    parser.add_argument('--sig-bundles', nargs='*', default=None, help='List of FLIRT .sig files to apply')
    return parser.parse_args(idc.ARGV[1:])

def apply_signatures(sig_bundles):
    if sig_bundles:
        for sig_path in sig_bundles:
            if not os.path.isfile(sig_path):
                print(f"[WARN] Signature file not found: {sig_path}")
                continue
            try:
                print(f"[INFO] Applying FLIRT signature: {sig_path}")
                idc.apply_sig(sig_path, 0)
            except Exception as e:
                print(f"[ERROR] Failed to apply signature {sig_path}: {e}")
    else:
        # Use IDA's default auto-apply
        print("[INFO] Auto-applying default FLIRT signatures.")
        idc.auto_apply_sig()

def extract_functions():
    functions = []
    for idx in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(idx)
        if not func:
            continue
        start_ea = func.start_ea
        name = ida_funcs.get_func_name(start_ea)
        functions.append({
            'offset': start_ea,
            'function_name': name
        })
    return functions

def get_sha256():
    try:
        return ida_nalt.retrieve_input_file_sha256().hex()
    except Exception:
        return None

def get_metadata():
    inf = idaapi.get_inf_structure()
    arch = 'intel' if inf.procName.lower().startswith('metapc') else inf.procName.lower()
    bitness = 64 if inf.is_64bit() else 32
    return arch, bitness

def main():
    args = parse_args()
    try:
        apply_signatures(args.sig_bundles)
        functions = extract_functions()
        arch, bitness = get_metadata()
        sha256 = get_sha256()
        report = {
            'architecture': arch,
            'base_addr': idaapi.get_imagebase(),
            'binary_size': idaapi.get_fileregion_offset(idaapi.get_fileregion_ea(idaapi.get_fileregion_offset(idaapi.get_imagebase()))),
            'bitness': bitness,
            'code_areas': [],
            'code_sections': [],
            'confidence_threshold': 0.0,
            'disassembly_errors': {},
            'execution_time': 0.0,
            'identified_alignment': 0,
            'message': 'IDA FLIRT analysis finished.',
            'metadata': {
                'binweight': 0.0,
                'component': '',
                'family': '',
                'filename': idaapi.get_root_filename(),
                'is_buffer': False,
                'is_library': False,
                'version': ''
            },
            'sha256': sha256 or '',
            'smda_version': 'IDA_FLIRT',
            'statistics': {
                'num_api_calls': 0,
                'num_basic_blocks': 0,
                'num_failed_functions': 0,
                'num_failed_instructions': 0,
                'num_function_calls': 0,
                'num_functions': len(functions),
                'num_instructions': 0,
                'num_leaf_functions': 0,
                'num_recursive_functions': 0
            },
            'status': 'ok',
            'timestamp': idaapi.get_kernel_version(),
            'xcfg': {},
            'functions': functions
        }
        with open(args.output, 'w') as fout:
            json.dump(report, fout, indent=1)
        print(f"[SUCCESS] Wrote SMDA-style report to {args.output}")
    except Exception as e:
        print(f"[FATAL ERROR] {e}\n{traceback.format_exc()}")
        sys.exit(2)
    finally:
        # Ensure IDA exits after script
        idaapi.qexit(0)

if __name__ == '__main__':
    main()