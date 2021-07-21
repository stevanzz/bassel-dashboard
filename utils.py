from urllib.parse import urlparse, urljoin
from flask import request


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


Admin = 'administrator'
Guard = 'guard'
Apartment_Owner = 'apartment_owner'


def get_default_page(user, isJS=False):
    if user.role == 'administrator':
        return '/users' if isJS else 'users'
    elif user.role == 'guard':
        return '/visitor-records' if isJS else 'visitorrecords'
    elif user.role == 'apartment_owner':
        return '/register-visitor' if isJS else 'registervisitorpage'
    else:
        return None