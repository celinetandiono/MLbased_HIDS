"""
File: data_preparation.py
Author: Celine Tandiono (based on John Ring)
Date: 28 February 2024
Description: Contains the code for data preparation for the ML training. ADFA sequences are decoded using the syscall mapping provided by Marcin Juszkiewicz.

References:
- John H. Ring IV, Colin M. Van Oort, Samson Durst, Vanessa White, Joseph P. Near, and Christian Skalka. 2021. Methods for Host-based Intrusion Detection with Deep Learning. Digit. Threat. Res. Pract. 2, 4, Article 26 (October 2021), 29 pages. https://doi.org/10.1145/3461462
- The syscalls-table repository on GitHub, maintained by Marcin Juszkiewicz, can be found at: [https://github.com/hrw/syscalls-table]
"""
#/usr/bin/python3

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import requests
from pathlib import Path
import tarfile
from utils.utils import get_path
import os

def syscall_mapping(arch="i386"):
    url = f"https://raw.githubusercontent.com/hrw/syscalls-table/master/data/tables/syscalls-{arch}"
    mapping = requests.get(url, allow_redirects=True).text.split("\n")
    
    syscall_map = {}
    for syscall in mapping: 
        tmp = syscall.split("\t")
        if len(tmp) == 1:
            continue

        syscall_map[tmp[1]] = tmp[0]
    return syscall_map

def extract_tarxz(tarxz_path):
    extract_path = tarxz_path.split(".")[0]
    with tarfile.open(get_path(tarxz_path)) as f:
            f.extractall(extract_path)   

def create_tar_xz(dataset):
    source_dir = get_path("../data/{dataset}")
    output_filename = get_path("../data/{dataset}.tar.xz")
    with tarfile.open(output_filename, "w:xz") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))

def adfa_decode():
    adfa_path = Path(get_path("../data/ADFA-LD"))
    if not adfa_path.exists():
         extract_tarxz(get_path("../data/ADFA-LD.tar.xz"))
    
    folder_name = "ADFA_decoded"
    
    mapping = syscall_mapping()
    for file in adfa_path.rglob("*.txt"):
        parts = list(file.parts)

        if parts[-3] == "Attack_Data_Master":
            parts[-4] = folder_name
            del parts[-5]
        else:    
            parts[-3] = "normal"
            parts[-4] = folder_name

        out_file = Path("/".join(parts))
        
        
        with open(file) as f:
            syscalls = f.readline().strip().split()
            sequence = []
            for syscall in syscalls:
                if syscall in mapping.keys():
                    sequence.append(mapping[syscall])
                else:
                    sequence.append(syscall)
                out_file.parent.mkdir(parents=True, exist_ok=True)
            if len(sequence):
                sequence = " ".join(sequence)
                with open(out_file, "w") as out:
                    out.write(sequence)

def merge_adfa_plaid():
    adfa_path = Path(get_path("../data/ADFA_decoded"))
    plaid_path = Path(get_path("../data/PLAID"))

    if not adfa_path.exists():
        adfa_decode()
    if not plaid_path.exists():
        extract_tarxz(get_path("../data/PLAID.tar.xz"))
    
    folder_name = "merged_data"
    for file in adfa_path.rglob("*.txt"):
        parts = list(file.parts)

        if parts[-3] == "Attack_Data_Master":
            parts[-4] = f"{folder_name}/attack"
        else:
            parts[-4] = f"{folder_name}"

        out_file = Path("/".join(parts))
        
        with open(file) as f:
            sequences = f.read()
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "w") as out:
                out.write(sequences)
    
    for file in plaid_path.rglob("*.txt"):
        parts = list(file.parts)
        parts[-5] = folder_name
        parts[-4] = "attack" if parts[-3] == "attack" else "normal"

        out_file = Path("/".join(parts))
        
        with open(file) as f:
            sequences = f.read()
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "w") as out:
                out.write(sequences)

if __name__ == "__main__":
    if not Path(get_path("../data/PLAID")).exists():
        extract_tarxz(get_path("../data/PLAID.tar.xz"))
    if not Path(get_path("../data/ADFA-LD")).exists():
        extract_tarxz(get_path("../data/ADFA-LD.tar.xz"))
        adfa_decode()

    merge_adfa_plaid()

