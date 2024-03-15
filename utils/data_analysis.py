"""
File: data_analysis.py
Author: Celine Tandiono
Date: 28 February 2024
Description: Contains the logic for analysing the ADFA and PLAID datasets. 
        Used to create the training mapping for the ML training to ensure consistency.
        Used to determine syscalls to trace based on occurence. 
"""

from pathlib import Path
import json
import tarfile
from utils import get_path

def data_analysis(dataset = "ADFA-LD"):
    """ Gets the unique system calls given a dataset
    """
    syscall_set = set()
    folder_path = Path(get_path(f"../data/{dataset}"))

    if not Path(folder_path).exists():
        with tarfile.open(get_path(f"../data/{dataset}.tar.xz")) as f:
            f.extractall(folder_path)

    count = 0
    for file_path in folder_path.rglob("*.txt"):                
        count += 1
        with open(file_path, 'r') as file:
            syscalls = file.read().split()
            for sys in syscalls:
                syscall_set.add(sys)

    print(f"{dataset} has {count} files")

    return syscall_set

def get_training_map(syscalls):
    """ Map unique syscalls to index for training purposes 
    Input:
        syscalls: list
            List of unique syscalls used in dataset
    Return:
        training_map: map
            Map consisting of syscalls mapped to index
    """

    training_map = {}
    idx = 1

    for i in syscalls:
        training_map[i] = idx
        idx += 1

    file_path = get_path("../utils/train_syscalls_map.json")
    with open(file_path, 'w') as file:
        json.dump(training_map, file)
    print(f"Set contents have been written to {file_path}")

def check_exit_exists():
    with open(get_path("train_syscalls_map.json")) as file:
        syscalls = json.load(file)

    with open(get_path("unable.txt")) as file:
        unable = file.read().split("\n")

    for line in unable:
        tmp = line.split()
        if len(tmp) == 2:
            try:
                original = tmp[0]
                change = tmp[1]
                syscalls[change] = syscalls[original]
                syscalls.pop(original)
            except:
                print(f"cannot find {tmp}")

    syscalls = dict(sorted(syscalls.items(), key=lambda item: item[1]))

    with open(get_path("changed_unable.txt"), 'w') as file:
        json.dump(syscalls, file)
    print(syscalls)

    with open(get_path("list_exit.txt")) as file:
        sysexit = file.read().split()
    
    for syscall in syscalls.keys():
        name = f"sys_exit_{syscall}"
        if name not in sysexit:
            print(syscall)

def syscall_occurence_analysis(dataset,folders):
    print(f"{dataset} occurence analysis")
    occurence = {}
    for folder in folders:
        folder_path = Path(get_path(folder))
        files = folder_path.rglob("*.txt")
        for file in files:
            with open(file) as file:
                syscalls = file.read().split()
            for syscall in syscalls:
                if syscall not in occurence.keys():
                    occurence[syscall] = 1
                else:
                    occurence[syscall] += 1

        occurence = dict(sorted(occurence.items(), key=lambda item: item[1]))    
    print(occurence)
    print("===================")
    with open(get_path(f"{dataset}.json"), 'w') as file:
        json.dump(occurence, file)

def map_syscall_to_occ():
    with open(get_path("train_syscalls_map.json")) as file:
        train_syscall = json.load(file)

    for file_type in ["normal", "attack"]:
        with open(get_path(f"{file_type}.json")) as file:
            normal = json.load(file)
        
        msg = ""
        for syscall in train_syscall:
            tmp = f"{syscall} {train_syscall[syscall]} "
            try: 
                tmp += f"{normal[syscall]}"
            except:
                print(f"{syscall} not in {file_type}")

            msg += tmp + "\n"
        with open(get_path(f"summary_{file_type}.txt"),'w') as file:
            file.write(msg)


if __name__ == "__main__":
    merge = set()

    for dataset in ["ADFA_decoded", "PLAID"]:
        syscalls = data_analysis(dataset)

        print(f"{dataset} has {len(syscalls)} unique syscalls")
        print(syscalls)
        merge = merge.union(syscalls)

    print(f"Total unique syscalls: {len(merge)}")
    merge = sorted(merge)

    get_training_map(merge)

    #with open(get_path("syscalls_to_attach.txt"), 'w') as file:
     #   file.write(str(merge))
    
    #datasets = {"attack": ["ADFA_decoded/Attack_Data_Master", "PLAID/PlAID/attack"], 
     #           "normal": ["ADFA_decoded/Training_Data_Master", "ADFA_decoded/Validation_Data_Master", "PLAID/PLAID/baseline"]}

    #for dataset in datasets:
     #   syscall_occurence_analysis(dataset, datasets[dataset])

    #map_syscall_to_occ()
    #check_exit_exists()
    
