"""
    test_authorization_django
    ~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import time
import types

import jwt
import pytest

from django.conf import settings
import authorization_django
from authorization_django import levels as authorization_levels

TESTSETTINGS = {
    'JWT_SECRET_KEY': 'testkey',
    'JWT_ALGORITHM': 'HS256',
    'LOGGER_NAME': 'authztest'
}


def create_request(tokendata, key, alg, prefix='Bearer'):
    return types.SimpleNamespace(META={
        'HTTP_AUTHORIZATION': "{} {}".format(prefix, str(
            jwt.encode(tokendata, key, algorithm=alg), 'utf-8'))
    })

now = int(time.time())

tokendata_correct = {
    'iat': now,
    'exp': now + 30,
    'authz': authorization_levels.LEVEL_EMPLOYEE_PLUS
}
tokendata_expired = {
    'iat': now - 10,
    'exp': now - 5
}

correct_request = create_request(
    tokendata_correct, TESTSETTINGS['JWT_SECRET_KEY'], TESTSETTINGS['JWT_ALGORITHM']
)

invalid_token_requests = (
    create_request(
        tokendata_correct, 'INVALID_KEY', TESTSETTINGS['JWT_ALGORITHM']
    ),
    create_request(
        tokendata_expired, TESTSETTINGS['JWT_SECRET_KEY'], TESTSETTINGS['JWT_ALGORITHM']
    )
)

malformed_requests = (
    create_request(
        tokendata_correct, TESTSETTINGS['JWT_SECRET_KEY'], TESTSETTINGS['JWT_ALGORITHM'], prefix='Bad'
    ),
    create_request(
        tokendata_correct, TESTSETTINGS['JWT_SECRET_KEY'], TESTSETTINGS['JWT_ALGORITHM'], prefix='Even Worse'
    ),
)

settings.configure(DEBUG=True)


def get_response(request):
    return True


@pytest.fixture()
def middleware():
    settings.DATAPUNT_AUTHZ = TESTSETTINGS
    return authorization_django.authorization_middleware(get_response)


def test_not_configured():
    with pytest.raises(authorization_django.AuthzConfigurationError):
        authorization_django.authorization_middleware(None)


def test_valid_request(middleware):
    middleware(correct_request)
    assert correct_request.is_authorized_for(authorization_levels.LEVEL_EMPLOYEE_PLUS)


def test_invalid_token_requests(middleware, capfd):
    for invalid_token_request in invalid_token_requests:
        response = middleware(invalid_token_request)
        assert response.status_code == 401
        assert 'WWW-Authenticate' in response
        assert 'invalid_token' in response['WWW-Authenticate']
        _, err = capfd.readouterr()
        assert 'Invalid JWT token' in err


def test_malformed_requests(middleware, capfd):
    for malformed_request in malformed_requests:
        response = middleware(malformed_request)
        assert response.status_code == 400
        assert 'WWW-Authenticate' in response
        assert 'invalid_request' in response['WWW-Authenticate']
        _, err = capfd.readouterr()
        assert 'Invalid Authorization header' in err


def test_no_authorization_header(middleware):
    empty_request = types.SimpleNamespace(META={})
    middleware(empty_request)
    assert not empty_request.is_authorized_for(authorization_levels.LEVEL_EMPLOYEE_PLUS)
    assert not empty_request.is_authorized_for(authorization_levels.LEVEL_EMPLOYEE)
    assert empty_request.is_authorized_for(authorization_levels.LEVEL_DEFAULT)


def test_unknown_config_param():
    settings.DATAPUNT_AUTHZ['lalaland'] = 'oscar'
    with pytest.raises(authorization_django.AuthzConfigurationError):
        authorization_django.authorization_middleware(None)
