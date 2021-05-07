"""
    authorization_django.middleware
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging
import json

from django import http
from jwcrypto.jwt import JWT, JWTExpired, JWTMissingKey
from jwcrypto.jws import InvalidJWSSignature

from .config import get_settings
from .jwks import get_keyset, check_update_keyset


class _AuthorizationHeaderError(Exception):

    def __init__(self, response):
        self.response = response


def authorization_middleware(get_response):
    """ Django middleware to parse incoming access tokens, validate them and
    set an authorization function on the request.

    The decision to use a generic middleware rather than an
    AuthenticationMiddleware is explicitly made, because inctances of the
    latter come with a number of assumptions (i.e. that user.is_authorized()
    exists, or that request.user uses the User model).

    Example usage:

    ::

        request.is_authorized_for()

    :param get_response: callable that creates the response object
    :return: response
    """
    middleware_settings = get_settings()
    logger = logging.getLogger(__name__)

    def always_ok(*_args, **_kwargs):
        return True

    def authorize_function(scopes, token_signature, x_unique_id=None):
        """ Creates a partial around :func:`levels.is_authorized`
        that wraps the current user's scopes.

        :return func:
        """
        log_msg_scopes = 'Granted access (needed: {}, granted: {}, token signature: {})'

        def is_authorized(*needed_scopes):
            granted_scopes = set(scopes)
            needed_scopes = set(needed_scopes)
            result = needed_scopes.issubset(granted_scopes)
            if needed_scopes and result:
                msg = log_msg_scopes.format(needed_scopes, granted_scopes, token_signature)
                if x_unique_id:
                    msg += ' X-Unique-ID: {}'.format(x_unique_id)
                logger.info(msg)
            return result

        return is_authorized

    def authorize_forced_anonymous(_):
        """ Authorize function for routes that are forced anonymous"""
        raise Exception('Should not call is_authorized_for in anonymous routes')

    def insufficient_scope():
        """Returns an HttpResponse object with a 401."""
        msg = 'Bearer realm="datapunt", error="insufficient_scope"'
        response = http.HttpResponse('Unauthorized', status=401)
        response['WWW-Authenticate'] = msg
        return response

    def expired_token():
        """ Returns an HttpResponse object with a 401
        """
        msg = 'Bearer realm="datapunt", error="expired_token"'
        response = http.HttpResponse('Unauthorized', status=401)
        response['WWW-Authenticate'] = msg
        return response

    def invalid_token():
        """ Returns an HttpResponse object with a 401
        """
        msg = 'Bearer realm="datapunt", error="invalid_token"'
        response = http.HttpResponse('Unauthorized', status=401)
        response['WWW-Authenticate'] = msg
        return response

    def invalid_request():
        """ Returns an HttpResponse object with a 400
        """
        msg = (
            "Bearer realm=\"datapunt\", error=\"invalid_request\", "
            "error_description=\"Invalid Authorization header format; "
            "should be: 'Bearer [token]'\"")
        response = http.HttpResponse('Bad Request', status=400)
        response['WWW-Authenticate'] = msg
        return response

    def token_data(authz_header):
        """ Get the token data present in the given authorization header.
        """
        try:
            prefix, raw_jwt = authz_header.split()
        except ValueError:
            logger.warning('Invalid authz header: {}'.format(authz_header))
            raise _AuthorizationHeaderError(invalid_request())

        if prefix.lower() != 'bearer':
            logger.warning('Invalid authz header: {}'.format(authz_header))
            raise _AuthorizationHeaderError(invalid_request())

        try:
            jwt = decode_token(raw_jwt)
        except JWTMissingKey:
            check_update_keyset()
            try:
                jwt = decode_token(raw_jwt)
            except JWTMissingKey as e:
                logger.warning('API authz problem: unknown key. {}'.format(e))
                raise _AuthorizationHeaderError(invalid_token())

        claims = get_claims(jwt)
        sub = claims['sub']
        scopes = claims['scopes']
        claims = claims['claims']
        token_signature = raw_jwt.split('.')[2]
        return scopes, token_signature, sub, claims

    def decode_token(raw_jwt):
        settings = get_settings()
        try:
            jwt = JWT(jwt=raw_jwt, key=get_keyset(), algs=settings['ALLOWED_SIGNING_ALGORITHMS'])
        except JWTExpired:
            logger.info(
                'API authz problem: token expired {}'.format(raw_jwt)
            )
            raise _AuthorizationHeaderError(invalid_token())
        except InvalidJWSSignature as e:
            logger.warning('API authz problem: invalid signature. {}'.format(e))
            raise _AuthorizationHeaderError(invalid_token())
        except ValueError as e:
            logger.warning(
                'API authz problem: {}'.format(e))
            raise _AuthorizationHeaderError(invalid_token())
        return jwt

    def get_claims(jwt):
        claims = json.loads(jwt.claims)
        if 'scopes' in claims:
            # Authz token structure
            return {
                'sub': claims.get('sub'),
                'scopes': claims['scopes'],
                'claims': claims
            }
        elif claims.get('realm_access'):
            # Keycloak token structure
            return {
                'sub': claims.get('sub'),
                'scopes': {convert_scope(r) for r in claims['realm_access']['roles']},
                'claims': claims
            }
        elif claims.get('groups') and (claims.get('unique_name') or claims.get('un')):
            # Azure AD token structure
            return {
                'sub': claims.get('unique_name', claims.get('un')),
                'scopes': {convert_scope(group.split(" ")[0]) for group in claims.get('groups')},
                'claims': claims
            }
        logger.warning(
            'API authz problem: access token misses scopes claim'
        )
        raise _AuthorizationHeaderError(invalid_token())

    def convert_scope(scope):
        """ Convert Keycloak role to authz style scope
        """
        return scope.upper().replace("_", "/")

    def method_is_protected(method, protected_methods):
        if method.upper() in protected_methods:
            return True
        return '*' in protected_methods and method.upper() != 'OPTIONS'

    def middleware(request):
        """ Parses the Authorization header, decodes and validates the JWT and
        adds the is_authorized_for function to the request.
        """

        # Config is set to ALWAYS OK, authorisation check disabled
        if middleware_settings['ALWAYS_OK']:
            logger.warning('API authz DISABLED')
            request.is_authorized_for = always_ok
            request.get_token_subject = 'ALWAYS_OK'
            return get_response(request)

        # Path is in forced anonymous routes or method is Options
        forced_anonymous = any(
            request.path.startswith(route)
            for route in middleware_settings['FORCED_ANONYMOUS_ROUTES'])

        if forced_anonymous or request.method == 'OPTIONS':
            request.is_authorized_for = authorize_forced_anonymous
            request.get_token_subject = None
            return get_response(request)

        PROTECTED = middleware_settings['PROTECTED']
        protected_resource = None
        for resource in PROTECTED:
            (route, protected_methods, required_scopes) = resource
            if request.path.startswith(route) and \
                    method_is_protected(request.method, protected_methods):
                protected_resource = resource
        if not protected_resource:
            return get_response(request)

        # Standard case
        scopes = []
        token_signature = ''
        subject = None
        claims = None

        x_unique_id = request.META.get('HTTP_X_UNIQUE_ID')
        authz_header = request.META.get('HTTP_AUTHORIZATION')

        if authz_header:
            try:
                scopes, token_signature, subject, claims = token_data(authz_header)
            except _AuthorizationHeaderError as e:
                return e.response

        authz_func = authorize_function(scopes, token_signature, x_unique_id)

        min_scope = middleware_settings['MIN_SCOPE']
        if len(min_scope) > 0 and not authz_func(*min_scope):
            return insufficient_scope()

        (route, protected_methods, required_scopes) = protected_resource
        if not authz_func(*required_scopes):
            return insufficient_scope()

        request.is_authorized_for = authz_func
        request.get_token_subject = subject
        request.get_token_scopes = scopes
        request.get_token_claims = claims
        return get_response(request)

    return middleware
