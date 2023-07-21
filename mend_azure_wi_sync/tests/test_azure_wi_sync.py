import pytest
from mend_azure_wi_sync.core import load_wi_json


def test_load_wi_json():
    assert load_wi_json()


if __name__ == '__main__':
    pytest.main()
