from requests import Request
from requests_cache import CachedResponse

import requests
import requests_cache
import tempfile
from os import path

def is_enabled():
    return session is _cached_session

def set_enabled(enabled):
    global session
    if enabled:
        if not _cached_session:
            raise Exception("Cached session must be created first")
        session = _cached_session
    else:
        session = _non_cache_session

def is_request_cached(request):
    if not is_enabled():
        return False
    key = session.cache.create_key(request)
    cached = session.cache.get_response(key)
    return cached and not cached.is_expired

def get_from_cache(request):
    if not is_enabled():
        return None
    return session.cache.get_response(session.cache.create_key(request))

def save_to_cache(request_key, response):
    if not is_enabled():
        return
    session.cache.save_response(response=response, cache_key=session.cache.create_key(request_key), expires=response.expires)

def create_redis_cached_session(connection, namespace='certvalidator_cache'):
    global _cached_session
    backend = requests_cache.backends.redis.RedisCache(namespace=namespace, connection=connection)
    _cached_session = requests_cache.CachedSession(namespace, backend=backend, cache_control=True, allowable_methods=['GET', 'POST'])


_cached_session = None
_non_cache_session = requests.Session()

session = _non_cache_session
