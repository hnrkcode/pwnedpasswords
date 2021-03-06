# Check if the password is compromised

Check if a password is safe to use without sending it online in plain text.

## Usage

To check a single password:
`python3 pwnedpasswords.py -p [password]` or `python3 pwnedpasswords.py --password [password]`

To check all passwords in a CSV-file:
`python3 pwnedpasswords.py -f [filepath]` or `python3 pwnedpasswords.py --csvfile [filepath]`

## How it works

The script takes a string of characters as an argument and creates a SHA-1 hash of that string.
Then it takes the five first characters of the SHA-1 hash and fetch hashes from leaked passwords with the same five first characters in their hashes, through the haveibeenpwned api.
Then it locally checks how many times the exact hash appear in the databases of leaked passwords.
