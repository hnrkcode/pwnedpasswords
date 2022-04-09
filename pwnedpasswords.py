import argparse
import csv
import hashlib
import sys
from collections import defaultdict

import requests


API_URL = "https://api.pwnedpasswords.com/range/"


def _hashify(password):
    """Returns an uppercase hash value of the password."""
    hash = hashlib.sha1()
    hash.update(bytes(password, encoding="utf-8"))

    return hash.hexdigest().upper()


def _get_matching_hash_count(suffix, data):
    """Locally count the hashes that matches the passwords hash."""
    occur = 0
    lines = data.text.split("\n")

    for line in lines:
        if line[:35] == suffix:
            occur = int(line[36:])

    return occur


def _message(password, occur):
    """Print the result to the screen."""
    if occur > 0:
        numerus = lambda num: "time." if num == 1 else "times!"
        print(f'"{password}" have been pwned {occur} {numerus(occur)}')
    elif occur == 0:
        print(f'No match for "{password}".')


def check_password(password, msg=False):
    """Hash password and check it against hashes of leaked passwords."""
    password_hash = _hashify(password)
    prefix, suffix = password_hash[:5], password_hash[5:]

    try:
        fetched_hashes = requests.get(f"{API_URL}{prefix}")
    except requests.exceptions.ConnectionError:
        sys.exit("Connection error.")

    occur = _get_matching_hash_count(suffix, fetched_hashes)

    if msg:
        _message(password, occur)

    return occur


def check_csv(file):
    column = defaultdict(list)
    try:
        with open(file) as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                for key, value in row.items():
                    column[key].append(value)
    except FileNotFoundError as e:
        sys.exit(e)
    else:
        for login_details in zip(column["username"], column["password"]):
            username = login_details[0]
            password = login_details[1]
            occur = check_password(password)

            if occur > 0:
                numerus = lambda num: "time." if num == 1 else "times!"
                print(
                    f'Password "{password}" for "{username}"',
                    f"appeared {occur} {numerus(occur)}",
                )


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--password", help="Check single password.")
    group.add_argument("-f", "--csvfile", help="Check passwords in CSV-file.")
    args = parser.parse_args()

    if args.password:
        check_password(args.password, msg=True)

    if args.csvfile:
        check_csv(args.csvfile)


if __name__ == "__main__":
    main()
