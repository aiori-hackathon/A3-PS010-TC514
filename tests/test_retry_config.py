import pytest

from netclass.config import Settings, load_settings


def test_default_is_two_retries_and_is_part_of_the_defaults():
    assert Settings().http_max_retries == 2
    assert load_settings({}).http_max_retries == 2


def test_retry_override_and_zero_disables_retries():
    assert load_settings({"NETCLASS_HTTP_MAX_RETRIES": "0"}).http_max_retries == 0
    assert load_settings({"NETCLASS_HTTP_MAX_RETRIES": "1"}).http_max_retries == 1


@pytest.mark.parametrize("value", ["3", "-1", "two", "1.5", "99"])
def test_retry_count_above_two_or_invalid_is_rejected(value):
    with pytest.raises(ValueError):
        load_settings({"NETCLASS_HTTP_MAX_RETRIES": value})
