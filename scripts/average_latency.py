#!/usr/bin/env python3
# Copyright 2024 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
import re
import argparse

def extract_overheads(log_file):
    overheads = []
    
    # Regular expression to match the log entries with txn overhead
    pattern = r'txn overhead:\s*([\d\.]+)'
    
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                overhead = float(match.group(1))
                overheads.append(overhead)
    
    return overheads

def calculate_average(overheads):
    if not overheads:
        return 0
    return sum(overheads) / len(overheads)

def main():
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="Extract and average txn overheads from a log file.")
    parser.add_argument('filename', type=str, help='The log file to process')
    
    # Parse the command-line arguments
    args = parser.parse_args()
    
    # Read the filename from the command line argument
    log_file = args.filename
    overheads = extract_overheads(log_file)
    
    if overheads:
        average_overhead = calculate_average(overheads)
        print(f"Average txn overhead: {average_overhead}")
    else:
        print("No txn overhead data found.")

if __name__ == "__main__":
    main()

