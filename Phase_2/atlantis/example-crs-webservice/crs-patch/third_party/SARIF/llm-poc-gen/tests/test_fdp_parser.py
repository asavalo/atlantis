from vuli.blobgen import FDPParser


def test_parse_string_to_byte():
    parser = FDPParser()
    result = parser.parse(
        """
```json
[
   { "method": "consumeRemainingAsBytes", "args": [], "value": "<?xml version=\\"1.0\\"?>"}
]
```
"""
    )
    assert result == [
        {
            "blob": b'<?xml version="1.0"?>',
            "script": str(
                [
                    {
                        "method": "consumeRemainingAsBytes",
                        "args": [],
                        "value": '<?xml version="1.0"?>',
                    }
                ]
            ),
        }
    ]


def test_string_to_jstring():
    parser = FDPParser()
    result = parser.parse(
        """
```json
[
   { "method": "consumeRemainingAsString", "args": [], "value": "<?xml version=\\"1.0\\"?>"}
]
```"""
    )
    assert result == [
        {
            "blob": b'<?xml version="1.0"?>',
            "script": str(
                [
                    {
                        "method": "consumeRemainingAsString",
                        "args": [],
                        "value": '<?xml version="1.0"?>',
                    }
                ]
            ),
        }
    ]


def test_bytes_to_jbytes():
    parser = FDPParser()
    result = parser.parse(
        """
```json
[
   { "method": "consumeRemainingAsBytes", "args": [], "value": "\xFF\x00"}
]
```"""
    )
    assert result == [
        {
            "blob": b"\xFF\x00",
            "script": str(
                [{"method": "consumeRemainingAsBytes", "args": [], "value": "\xFF\x00"}]
            ),
        }
    ]


def test_string_null_and_number():
    parser = FDPParser()
    result = parser.parse(
        """
```json
[
    {"method": "consumeInt", "args": [], "value": 11},
    {"method": "consumeRemainingAsString", "args": [], "value": "name\\0localhost\\0port\\0443\\0https://example.com"}
]
```"""
    )
    assert result == [
        {
            "blob": b"name\xc0\x80localhost\xc0\x80port\xc0\x80443\xc0\x80https://example.com\x0b\x00\x00\x00",
            "script": str(
                [
                    {"method": "consumeInt", "args": [], "value": 11},
                    {
                        "method": "consumeRemainingAsString",
                        "args": [],
                        "value": "name\x00localhost\x00port\x00443\x00https://example.com",
                    },
                ]
            ),
        }
    ]
