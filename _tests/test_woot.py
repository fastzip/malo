import pytest

from woot import compile

def test_empty():
    assert compile("") == []
    assert compile(" #comment") == []

def test_bytes():
    assert compile("byte 21") == [0x21]
    assert compile("byte 1 2 3") == [1, 2, 3]

def test_start_is_bytes():
    assert compile("21") == [0x21]
    assert compile("1 2 3") == [1, 2, 3]

def test_bits():
    assert compile("bit 1 0 0 1") == [9]
    assert compile("bit 1001") == [9]
    assert compile("bit 1001000001") == [9, 2]

def test_sync():
    assert compile("bit 10 sync 101") == [1, 5]

def test_noncompliant_input():
    with pytest.raises(ValueError):
        compile("x")

    with pytest.raises(ValueError):
        compile("bits 1")
