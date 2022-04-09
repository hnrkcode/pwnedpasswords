import argparse
import csv
import hashlib
import os
import sys
from collections import defaultdict

import requests


class CheckCSV:
    def __init__(self):
        self.password = CheckPassword(False)

    def _message(self, username, password, occur):
        """Print the result to the screen."""
        if occur > 0:
            numerus = lambda num: "time." if num == 1 else "times!"
            print(
                f'Password "{password}" for "{username}"',
                f"appeared {occur} {numerus(occur)}",
            )

    def check(self, file):
        """Hash and check all passwords in a CSV-file."""
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
            for login_details in zip(column['username'], column['password']):
                username = login_details[0]
                password = login_details[1]
                occur = self.password.check(password)
                self._message(username, password, occur)



class CheckPassword:
    def __init__(self, msg=True):
        self.url = "https://api.pwnedpasswords.com/range/"
        self.temp = os.path.join(os.path.dirname(__file__), "hashes.txt")
        self.msg = msg

    def _hashify(self, password):
        """Returns an uppercase hash value of the password."""
        hash = hashlib.sha1()
        hash.update(bytes(password, encoding="utf-8"))
        return hash.hexdigest().upper()

    def _save_temp(self, hashes):
        """Temporary store the fetched hashes in a file."""
        with open(self.temp, "w") as output:
            output.write(hashes)

    def _remove_temp(self):
        """Delete the temporary file with fetched hashes."""
        os.remove(self.temp)

    def _count(self, suffix):
        """Locally count the hashes that matches the passwords hash."""
        occur = 0
        with open(self.temp) as f:
            for line in f.readlines():
                if line[:35] == suffix:
                    occur = int(line[36:])
        self._remove_temp()
        return occur

    def _message(self, password, occur):
        """Print the result to the screen."""
        if occur > 0:
            numerus = lambda num: "time." if num == 1 else "times!"
            print(f'"{password}" have been pwned {occur} {numerus(occur)}')
        elif occur == 0:
            print(f'No match for "{password}".')

    def check(self, password):
        """Hash password and check it against hashes of leaked passwords."""
        password_hash = self._hashify(password)
        prefix, suffix = password_hash[:5], password_hash[5:]
        try:
            fetched_hashes = requests.get(f"{self.url}{prefix}")
        except requests.exceptions.ConnectionError:
            sys.exit("Connection error.")
        else:
            # Temporary store the fetched hashes in a file.
            self._save_temp(fetched_hashes.text)
            # Locally count the hashes that matches the passwords hash.
            occur = self._count(suffix)
            if self.msg:
                self._message(password, occur)
            return occur


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--password", help="Check single password.")
    group.add_argument("-f", "--csvfile", help="Check passwords in CSV-file.")
    args = parser.parse_args()

    if args.password:
        haveibeenpwned = CheckPassword()
        haveibeenpwned.check(args.password)
    else:
        check_csv = CheckCSV()
        check_csv.check(args.csvfile)


if __name__ == "__main__":
    main()
