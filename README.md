# Check if the password is compromised

Check if a password is safe to use without sending it online in plain text.

## Usage

To check a single password:

```
python run.py -p [password]

python run.py --password [password]
```

To check all passwords in a CSV-file:

```
python run.py -f [filepath]

python run.py --csvfile [filepath]
```

## How it works

The script takes a string of characters as an argument and creates a SHA-1 hash of that string.

Then it takes the five first characters of the SHA-1 hash and fetch hashes from leaked passwords with the same five first characters in their hashes, through the haveibeenpwned api.

Then it locally checks how many times the exact hash appear in the databases of leaked passwords.

## Run tests

```
pytest
```

## Type checking with mypy

```
mypy pwnedpasswords/__init__.py
```
