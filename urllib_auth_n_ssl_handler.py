#!/usr/bin/env python
__all__ = ['match_hostname', 'CertificateError']
import base64
import socket
import ssl
import re
from six.moves import http_client
from six.moves import urllib


class HTTPBasicPriorAuthHandler(urllib.request.HTTPBasicAuthHandler):
    """
    Preemptive basic auth.

    Instead of waiting for a 403 to then retry with the credentials,
    send the credentials if the url is handled by the password manager.
    Note: please use realm=None when calling add_password.
    """

    # Jenkins does not send a 401 error code for retry and 403 Forbidden is sent.
    # https://wiki.jenkins.io/display/JENKINS/Authenticating+scripted+clients
    # In urllib2 there is no preemptive authorization handling. This has been solved for python 3.5+.
    # The below class is an implementation suggested in a patch for urllib2
    # https://bugs.python.org/file36344/fix-issue19494-py27.patch
    # https://bugs.python.org/issue19494
    def http_request(self, req):
        if not req.has_header('Authorization'):
            user, passwd = self.passwd.find_user_password(None, req.host)
            if user and passwd:
                credentials = '{0}:{1}'.format(user, passwd).encode()
                auth_str = base64.standard_b64encode(credentials).decode()
                req.add_unredirected_header('Authorization',
                                            'Basic {0}'.format(auth_str.strip()))
        return req


class CertificateError(ValueError):
    pass


def match_hostname(cert, hostname):
    if not cert:
        raise ValueError("empty or no certificate")
    dnsnames = []
    san = cert.get('subjectAltName', ())
    for key, value in san:
        if key == 'DNS':
            if _dnsname_to_pat(value).match(hostname):
                return
            dnsnames.append(value)
    if not dnsnames:
        for sub in cert.get('subject', ()):
            for key, value in sub:
                if key == 'commonName':
                    if _dnsname_to_pat(value).match(hostname):
                        return
                    dnsnames.append(value)
    if len(dnsnames) > 1:
        raise CertificateError("hostname %r doesn't match either of %s" % (
            hostname,
            ', '.join(map(repr, dnsnames))))
    elif len(dnsnames) == 1:
        raise CertificateError("hostname %r doesn't match %r" % (
            hostname,
            dnsnames[0]))
    else:
        raise CertificateError("no appropriate commonName or \
                                subjectAltName fields were found")


def _dnsname_to_pat(dn):
    pats = []
    for frag in dn.split(r'.'):
        if frag == '*':
            pats.append('[^.]+')
        else:
            frag = re.escape(frag)
            pats.append(frag.replace(r'\*', '[^.]*'))
    return re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)


class HTTPSConnection(http_client.HTTPSConnection):
    def __init__(self, host, **kwargs):
        self.ca_certs = kwargs.pop('ca_certs', None)
        self.checker = kwargs.pop('checker', match_hostname)
        http_client.HTTPSConnection.__init__(self, host, **kwargs)

    def connect(self):
        args = [(self.host, self.port), self.timeout, ]
        if hasattr(self, 'source_address'):
            args.append(self.source_address)
        sock = socket.create_connection(*args)

        if getattr(self, '_tunnel_host', None):
            self.sock = sock
            self._tunnel()
        kwargs = {}
        if self.ca_certs is not None:
            kwargs.update(
                cert_reqs=ssl.CERT_REQUIRED,
                ca_certs=self.ca_certs)
        self.sock = ssl.wrap_socket(sock,
                                    keyfile=self.key_file,
                                    certfile=self.cert_file,
                                    **kwargs)
        if self.checker is not None:
            try:
                self.checker(self.sock.getpeercert(), self.host)
            except CertificateError:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                raise


class HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, user=None, passwd=None, key_file=None, cert_file=None, ca_certs=None,
                 checker=match_hostname):
        urllib.request.HTTPSHandler.__init__(self)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_certs = ca_certs
        self.checker = checker
        self.user = user
        self.passwd = passwd

    def https_open(self, req):
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, **kwargs):
        d = dict(cert_file=self.cert_file,
                 key_file=self.key_file,
                 ca_certs=self.ca_certs,
                 checker=self.checker)
        d.update(kwargs)
        return HTTPSConnection(host, **d)

    """
        Preemptive basic auth.

        Instead of waiting for a 403 to then retry with the credentials,
        send the credentials if the url is handled by the password manager.
        Note: please use realm=None when calling add_password.
        """

    # Jenkins does not send a 401 error code for retry and 403 Forbidden is sent.
    # https://wiki.jenkins.io/display/JENKINS/Authenticating+scripted+clients
    # In urllib2 there is no preemptive authorization handling. This has been solved for python 3.5+.
    # The below class is an implementation suggested in a patch for urllib2
    # https://bugs.python.org/file36344/fix-issue19494-py27.patch
    # https://bugs.python.org/issue19494
    def https_request(self, req):
        if not req.has_header('Authorization'):
            if self.user and self.passwd:
                credentials = '{0}:{1}'.format(self.user, self.passwd).encode()
                auth_str = base64.standard_b64encode(credentials).decode()
                req.add_unredirected_header('Authorization',
                                            'Basic {0}'.format(auth_str.strip()))
        return req


__all__.append('HTTPSHandler')
