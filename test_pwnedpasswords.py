from pwnedpasswords import _hashify, _get_matching_hash_count


def test_hashify():
    assert _hashify("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_get_matching_hash_count():
    with open("test_hashes.txt") as f:
        data = f.read()
        password_hash = _hashify("password")
        _, suffix = password_hash[:5], password_hash[5:]
        assert password_hash == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        assert _get_matching_hash_count(suffix, data) == 9545824
