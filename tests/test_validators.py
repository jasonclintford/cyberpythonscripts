from cyberkit.core.validators import is_valid_cidr, is_valid_hostname, is_valid_ip, is_valid_url


def test_ip_and_cidr_validation() -> None:
    assert is_valid_ip("192.168.1.1")
    assert not is_valid_ip("999.1.1.1")
    assert is_valid_cidr("10.0.0.0/24")
    assert not is_valid_cidr("10.0.0.0/99")


def test_hostname_validation() -> None:
    assert is_valid_hostname("example.com")
    assert is_valid_hostname("sub-domain.internal")
    assert not is_valid_hostname("-badhost")


def test_url_validation() -> None:
    assert is_valid_url("https://example.com")
    assert is_valid_url("http://localhost:8080/path")
    assert not is_valid_url("ftp://example.com")
