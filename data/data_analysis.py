import os
import requests
from pathlib import Path
import json

def get_path(name):
    relative_path = os.path.join(os.path.dirname(__file__), name)
    absolute_path = os.path.abspath(relative_path)  
    return absolute_path

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

def data_analysis(syscall_map = None, dataset = "ADFA-LD"):
    syscall_set = set()
    folder_path = Path(get_path(f"{dataset}"))
    count = 0
    for file_path in folder_path.rglob("*.txt"):                
        count += 1
        with open(file_path, 'r') as file:
            syscalls = [value for value in file.read().split()]
            for sys in syscalls:
                if dataset == "PLAID":
                    syscall_set.add(sys)
                else:
                    syscall_set.add(syscall_map[sys])

    print(f"{dataset} has {count} files")

    return syscall_set

def get_training_map(syscalls):
    """ Map syscalls to incremental index for training purposes 
    Input:
        syscalls: list
            List of unique syscalls used in dataset
    Return:
        training_map: map
            Map consisting of syscalls mapped to index
    """

    training_map = {}
    idx = 1

    for i in merge:
        training_map[i] = idx
        idx += 1

    return training_map
    

if __name__ == "__main__":
    arch_mapping = syscall_mapping()
    merge = set()

    for dataset in ["ADFA-LD", "PLAID"]:
        syscalls = data_analysis(arch_mapping, dataset)

        print(f"{dataset} has {len(syscalls)} unique syscalls")
        print(syscalls)
        merge = merge.union(syscalls)

    print(f"Total unique syscalls: {len(merge)}")
    merge = sorted(merge)

    training_map = get_training_map(merge)
    # Write the string to a file
    file_path = get_path("train_syscalls_map.json")
    with open(file_path, 'w') as file:
        json.dump(training_map, file)
    print(f"Set contents have been written to {file_path}")

