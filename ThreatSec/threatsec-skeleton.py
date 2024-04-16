#!/usr/local/bin/python3

# Course: CS 461 ThreatSec MP
# Author: Adam Bates

import argparse
import csv
from enum import Enum
from functools import reduce
import json
import os
import pdb
import sys
from typing import Dict
from typing import List
from typing import Tuple

from trie import Trie

ProcessName = str
Tid = int
SyscallId = int

# Enumeration of system calls to map them to
#   specific integer values.
# One way to retreieve a system call's ID is
#   as follows: SYSCALL_IDS["open"].value
# System calls encountered in the log
#   that do not appear in the enumeration
#   should be mapped to SYSCALL_ID.unknown.
SYSCALL_IDS = Enum('syscall_ids', ["accept","access","bind",
                                   "chmod","clone","close",
                                   "connect","execve","fstat",
                                   "ftruncate","listen","mmap2",
                                   "open","read","recv",
                                   "recvfrom","recvmsg","send",
                                   "sendmsg","sendto","stat",
                                   "truncate","unlink","waitpid",
                                   "write","writev","unknown"])

# Interface and required command line arguments for program
parser = argparse.ArgumentParser(description='CS 461 ThreatSec MP.')
parser.add_argument('-d', '--database', type=str,
                    help='path to log file/directory for creating database (i.e., training data)')
parser.add_argument('-t', '--test', type=str,
                    help='path to log file for testing the database (i.e., test data)')
parser.add_argument('-s', '--seqlength', type=int,
                    help='sequence length (window size) used for system calls')
parser.add_argument('-o', '--output', type=str,
                    help='name of file for test output. Print to STDOUT by default if omitted')

# Provides a 'cleaned' version of the process name to use in your analysis.
#   The log files we're using have this annoying habit of assigning multiple process names
#   to the same executable by instance number, e.g., "mozStorage #1", "mozStorage #2."
#   Treating these as unique programs reduces the number of observations we have per program
#   and will increase the error rate. This function just lobs off the number.
def clean_process_name(process_name):
    return process_name.split(" #")[0]


# We have started the log parsing function for you to make sure that we're
#   all being consistent in how we interpret the log fields.
#   Do not edit the loop logic for extracting log fields,
#   cleaning the process name, or setting pid to tid.
def parse_log(log_file):

    grouped_syscalls = {}

    # Note: this code assumes log_file is a file (not a dir).
    #   you will need to wrap or edit this function to support directories.
    with open(log_file,"r") as log:
        logreader = csv.reader(log, delimiter=",", skipinitialspace=True)
        next(logreader) # skip headers
        for event in logreader:

            # Retrieve relevant log fields
            try:
                (ret_val, ret_time, call_time, process_name, pid, tid, syscall) = event[:7] 
            except:
                # There are some badly-formed lines in some of our log data
                #   due to, e.g., incorrectly escaped syscall arguments.
                #   For our purposes we're just going to drop these and continue
                continue

            # Cleaning up process names so that processes running the same executable
            # are grouped together in the database, see helper function.
            process_name = clean_process_name(process_name)
            
            # We are going to use the thread identifier as the process identifier.
            #   As a reminder, pid==tid in a single threaded process.
            #   Just setting pid equal to tid here to avoid any confusion.
            tid = int(tid)
            pid = tid
            
            if syscall in SYSCALL_IDS.__members__:
                syscall_id = SYSCALL_IDS[syscall].value
            else:
                syscall_id = SYSCALL_IDS.unknown.value

            key = (process_name, pid)

            if key not in grouped_syscalls:
                grouped_syscalls[key] = []

            grouped_syscalls[key].append(syscall_id)
    
    print(f"[Parse log] {log_file} Number of Syscall Traces: {len(grouped_syscalls)}")
    return grouped_syscalls                


def parse_logs(log_file_path: str) -> List[Dict[Tuple[ProcessName, Tid], List[int]]]:
    if os.path.isfile(log_file_path):
        syscall_traces_dicts = [parse_log(log_file_path)]
    else:
        syscall_traces_dicts = [parse_log(os.path.join(log_file_path, filename)) for filename in os.listdir(log_file_path) if os.path.isfile(os.path.join(log_file_path, filename))]
    print(f"[parse_logs] Total Number of Syscall Traces: {sum([len(syscall_trace_dict) for syscall_trace_dict in syscall_traces_dicts])}")
    return syscall_traces_dicts


def generate_database(sycall_trace_dicts: List[Dict[Tuple[ProcessName, Tid], List[int]]], window_size: int) -> Dict[ProcessName, Trie]:

    db = {}
    unique_db = Trie()

    for sycall_trace_dict in sycall_trace_dicts:
        for (process_name, tid), syscalls_trace in sycall_trace_dict.items():
            if process_name not in db:
                db[process_name] = Trie()
            for i in range(len(syscalls_trace)):
                window = syscalls_trace[i : i + window_size]
                while len(window) < window_size:
                    window.append(SYSCALL_IDS.unknown.value)
                db[process_name].insert(window)
                unique_db.insert(window)
    
    for process_name, process_name_trie in db.items():
        print("[Database] ", process_name, " Syscall Sequences: ", process_name_trie.count_paths())
    print("[Database] Total Unique Syscall Sequences: ", unique_db.count_paths())

    for k, t in db.items():
        t.pretty_print_trie("tmp/" + k.replace(" ", "%").replace("/", "%"))
    
    return db


def forrest_ids_algorithm(
    syscall_traces_db: Dict[ProcessName, Trie], 
    test_syscall_traces_dicts: List[Dict[Tuple[ProcessName, Tid], List[SyscallId]]], 
    output_file: str,
    window_size: int
):
    """
    For each (process_name, tid) pair, also calculate its percentage anomaly 
    for that process, i.e. Num.Anomalies/Num.Sequences. If there does not 
    exist as database for process_name because it was not observed in the 
    training data, set anomaly count to -99 for that (process_name, tid) pair.
    """

    output = {}

    with open(output_file, "w") as output_file:
        writer = csv.writer(output_file)
        for test_syscall_traces_dict in test_syscall_traces_dicts:
            for (process_name, tid), test_syscall_trace in test_syscall_traces_dict.items():
                if process_name not in syscall_traces_db:
                    if (process_name, tid) not in output:
                        output[(process_name, tid)] = {
                            "num_anomalies": -99,
                            "num_sequences": 0
                        }
                else:
                    num_anomalies = 0
                    num_sequences = 0
                    for i in range(len(test_syscall_trace)):
                        window = test_syscall_trace[i : i + window_size]
                        while len(window) < window_size:
                            window.append(SYSCALL_IDS.unknown.value)
                        if not syscall_traces_db[process_name].search(window):
                            # if process_name == "Gecko_IOThread":
                            #     print(window)
                            num_anomalies += 1
                        num_sequences += 1
                    if (process_name, tid) not in output:
                        output[(process_name, tid)] = {
                            "num_anomalies": num_anomalies,
                            "num_sequences": num_sequences
                        }
                    else:
                        output[(process_name, tid)]["num_anomalies"] += num_anomalies
                        output[(process_name, tid)]["num_sequences"] += num_sequences
        
        csv_rows = []
        for (process_name, tid), data in output.items():
            if data["num_anomalies"] == -99:
                csv_rows.append([process_name, tid, -99, "100%"])
            else:
                csv_rows.append([process_name, tid, data["num_anomalies"], f"{data['num_anomalies'] / data['num_sequences'] * 100}%" if data["num_sequences"] > 0 else "100%"])
        writer.writerows(sorted(csv_rows, key=lambda x: (x[0], x[1])))

if __name__ == "__main__":
    """
    3.1.1
        python3 threatsec-skeleton.py -d train/cnn_train -t test/attack_test -s 6
        python3 threatsec-skeleton.py -d train/ -t test/attack_test -s 6
    3.1.2
        python3 threatsec-skeleton.py -d train/gmail_train -t test/attack_test -s 6
        python3 threatsec-skeleton.py -d train/ -t test/attack_test -s 6
    3.1.3
        python3 threatsec-skeleton.py -d train/ -t test/youtube_test -s 6 -o sol_3.1.3_benign_seq6.csv
        python3 threatsec-skeleton.py -d train/ -t test/youtube_test -s 10 -o sol_3.1.3_benign_seq10.csv
        python3 threatsec-skeleton.py -d train/ -t test/attack_test -s 6 -o sol_3.1.3_attack_seq6.csv
        python3 threatsec-skeleton.py -d train/ -t test/attack_test -s 10 -o sol_3.1.3_attack_seq10.csv
    """

    args = parser.parse_args()

    if not (os.path.isfile(args.database) or os.path.isdir(args.database)):
        print("Error: %s is not a valid file path" % (args.database), file=sys.stderr)
        sys.exit(1)
        
    if not os.path.isfile(args.test):
        print("Error: %s is not a valid file path" % (args.test), file=sys.stderr)
        sys.exit(2)
    
    print(f"\nParsing {args.database} syscalls...")
    training_syscall_traces_dicts = parse_logs(args.database)

    print("\nGenerating database...")
    trained_syscall_traces_db = generate_database(training_syscall_traces_dicts, args.seqlength)

    print(f"\nParsing {args.test} syscalls...")
    test_syscall_traces_dicts = parse_logs(args.test)

    print("Running IDS Alogrithm...")
    forrest_ids_algorithm(trained_syscall_traces_db, test_syscall_traces_dicts, args.output, args.seqlength)
