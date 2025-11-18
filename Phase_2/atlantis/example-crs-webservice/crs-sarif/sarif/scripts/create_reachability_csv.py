#!/usr/bin/env python3

import csv
import os
import re
import sys

test_cases = {
    "c": [
        "asc-nginx_cpv-10",
        "asc-nginx_cpv-11",
        "asc-nginx_cpv-12",
        "asc-nginx_cpv-13",
        "asc-nginx_cpv-14",
        "asc-nginx_cpv-15",
        "asc-nginx_cpv-17",
        "asc-nginx_cpv-1",
        "asc-nginx_cpv-2",
        "asc-nginx_cpv-3",
        "asc-nginx_cpv-4",
        "asc-nginx_cpv-5",
        "asc-nginx_cpv-8",
        "asc-nginx_cpv-9",
        "babynginx_cpv-0",
        "babynote_cpv-0",
        "concolic-test_cpv-0",
        "concolic-test_cpv-1",
        "itoa_cpv-0",
        "itoa_cpv-1",
        "libcue_cpv-0",
        "mock-c_cpv-0",
        "mock-c_cpv-1",
        "mock-cp_cpv-1",
        "mock-cp_cpv-2",
        "rpn-calculator_cpv-0",
        "rpn-calculator_cpv-1",
        "user-nginx_cpv-0",
        "user-nginx_cpv-2",
        "user-nginx_cpv-3",
        "user-nginx_cpv-4",
        "user-nginx_cpv-5",
        "user-nginx_cpv-6",
        "user-nginx_cpv-7",
        "user-nginx_cpv-8",
    ],
    "java": [
        "ActivemqOneCPVEight",
        "ActivemqOneCPVEleven",
        "ActivemqOneCPVFive",
        "ActivemqOneCPVFour",
        "ActivemqOneCPVNine",
        "ActivemqOneCPVOne",
        "ActivemqOneCPVSeven",
        "ActivemqOneCPVSix",
        "ActivemqOneCPVTen",
        "ActivemqOneCPVThree",
        "ActivemqOneCPVTwelve",
        "ActivemqOneCPVTwo",
        "AerospikeOneCPVOne",
        "BatikOneCPVOne",
        "BCELOneCPVOne",
        "BeanUtilsOneCPVOne",
        "CXFOneCPVOne",
        "CXFThreeCPVOne",
        "CXFTwoCPVOne",
        "FuzzyOneCPVOne",
        "GeonetworkOneCPVOne",
        "HtmlunitOneCPVOne",
        "ImagingOneCPVOne",
        "ImagingOneCPVThree",
        "ImagingOneCPVTwo",
        "ImagingTwoCPVOne",
        "JacksonDatabindOneCPVOne",
        "MailApiHarnessOneCPVOne",
        "JenkinsFiveCPVOne",
        "JenkinsFiveCPVTwo",
        "JenkinsFourCPVOne",
        "JenkinsFourCPVTwo",
        "JenkinsOneCPVOne",
        "JenkinsOneCPVTwo",
        "JenkinsThreeCPVEight",
        "JenkinsThreeCPVEleven",
        "JenkinsThreeCPVFive",
        "JenkinsThreeCPVFour",
        "JenkinsThreeCPVNine",
        "JenkinsThreeCPVOne",
        "JenkinsThreeCPVSeven",
        "JenkinsThreeCPVSix",
        "JenkinsThreeCPVTen",
        "JenkinsThreeCPVThree",
        "JenkinsThreeCPVTwo",
        "JenkinsTwoCPVOne",
        "KylinOneCPVOne",
        "OlingoOneCPVOne",
        "OripaOneCPVOne",
        "Pac4jOneCPVOne",
        "Rdf4jOneCPVOne",
        "Rdf4jOneCPVThree",
        "Rdf4jOneCPVTwo",
        "TikaOneCPVOne",
        "TikaTwoCPVOne",
        "WidocoOneCPVOne",
        "ZTZIPOneCPVOne",
    ],
}


def _match_sarif_name(file_name, language):
    # remove the language prefix using basic search in testcase
    for test_case in test_cases[language]:
        if test_case in file_name:
            return test_case

    raise ValueError(f"Could not find test case for {file_name}")


def parse_stats_file(file_path, language):
    results = {}

    with open(file_path, "r") as f:
        content = f.read()

        # Parse failed files
        failed_section = re.search(
            r"\[\+\] Failed SARIF files:\n(.*?)\n\n", content, re.DOTALL
        )
        if failed_section:
            failed_files = failed_section.group(1).strip().split("\n")
            for file in failed_files:
                base_name = _match_sarif_name(file, language)
                results[base_name] = "X"

        # Parse success files
        success_section = re.search(
            r"\[\+\] Success SARIF files:\n(.*?)\n\n", content, re.DOTALL
        )
        if success_section:
            success_files = success_section.group(1).strip().split("\n")
            for file in success_files:
                base_name = _match_sarif_name(file, language)
                results[base_name] = "O"

        # Parse unknown files
        unknown_section = re.search(
            r"\[\+\] Unknown SARIF files:\n(.*?)\n\n", content, re.DOTALL
        )
        if unknown_section:
            unknown_files = unknown_section.group(1).strip().split("\n")
            for file in unknown_files:
                base_name = _match_sarif_name(file, language)
                results[base_name] = "ERR"

    return results


def create_csv(all_results, stats_files, language, output_file="combined_results.csv"):
    # Define the column order for test cases

    # Create header row
    headers = ["Stats File"] + stats_files

    # Create rows with results
    rows = [headers]  # Start with headers

    for sarif_name in test_cases[language]:
        row = [sarif_name]
        for stats_file in stats_files:
            try:
                row.append(all_results[stats_file][sarif_name])
            except KeyError:
                row.append("ERR")
        rows.append(row)

    # Write to CSV
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: python3 create_results_csv.py <language> <stats_file1> [stats_file2 ...]"
        )
        print(
            "Example: python3 create_results_csv.py c reachability_analysis_stats_basic-forward.txt"
        )
        sys.exit(1)

    all_results = {}
    base_names = []
    language = sys.argv[1]
    out_dir = f"./data/{language}/out/"
    output_file = f"{out_dir}/reachability_combined_results.csv"
    stats_files = sys.argv[2:]
    for stats_file in stats_files:
        if not os.path.exists(stats_file):
            print(f"Error: File {stats_file} does not exist")
            continue

        # Use the basename of the stats file as the key
        base_name = os.path.splitext(os.path.basename(stats_file))[0]
        base_names.append(base_name)
        results = parse_stats_file(stats_file, language)
        all_results[base_name] = results

    # with open("all_results.json", "w") as f:
    #     json.dump(all_results, f)

    create_csv(all_results, base_names, language, output_file)
    print(f"Results have been written to {output_file}")


if __name__ == "__main__":
    main()
