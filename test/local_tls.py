"""
Local, self-contained TLS test infrastructure.

Generates a temporary CA and leaf certificates with the system ``openssl``
command line tool so the TLS tests do not depend on the optional
``cryptography`` package or on any external server.
"""

import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading


class CertificateAuthority(object):
    def __init__(self, directory, common_name='ldap3 test root ca'):
        self.directory = directory
        self.key_file = os.path.join(directory, 'ca.key')
        self.cert_file = os.path.join(directory, 'ca.crt')
        self._run([
            'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', self.key_file, '-out', self.cert_file,
            '-days', '3650', '-subj', '/CN=%s' % common_name,
        ])

    def issue_cert(self, name, dns_names=(), ip_names=(), common_name=None,
                   expired=False, self_signed=False, wildcard=False):
        key_file = os.path.join(self.directory, name + '.key')
        csr_file = os.path.join(self.directory, name + '.csr')
        cert_file = os.path.join(self.directory, name + '.crt')

        subject_cn = common_name if common_name is not None else (dns_names[0] if dns_names else 'ldap3-test')
        self._run([
            'req', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', key_file, '-out', csr_file,
            '-subj', '/CN=%s' % subject_cn,
        ])

        san_entries = ['DNS:%s' % value for value in dns_names]
        if wildcard and dns_names:
            san_entries = ['DNS:*.%s' % dns_names[0]] + san_entries[1:]
        san_entries.extend('IP:%s' % value for value in ip_names)

        ext_file = os.path.join(self.directory, name + '.ext')
        with open(ext_file, 'w') as handle:
            handle.write('basicConstraints=CA:FALSE\n')
            if san_entries:
                handle.write('subjectAltName=%s\n' % ','.join(san_entries))

        command = ['x509', '-req', '-in', csr_file]
        if self_signed:
            command.extend(['-signkey', key_file])
        else:
            command.extend(['-CA', self.cert_file, '-CAkey', self.key_file, '-CAcreateserial'])
        if expired:
            command.extend(['-not_before', '20000101000000Z', '-not_after', '20010101000000Z'])
        else:
            command.extend(['-days', '3650'])
        command.extend(['-extfile', ext_file, '-out', cert_file])
        self._run(command)
        return key_file, cert_file

    @staticmethod
    def _run(arguments):
        completed = subprocess.run(
            ['openssl'] + arguments,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if completed.returncode != 0:
            raise RuntimeError('openssl %s failed: %s' % (arguments[0], completed.stderr.decode('utf-8', 'replace')))


class InMemoryTlsServer(object):
    """In-process TLS endpoint backed by a socketpair.

    The sandbox used for the test suite forbids binding TCP ports, so the
    client side of the pair is handed directly to the ldap3 Tls object. The
    server thread records whether a handshake completed and the SNI name.
    """

    def __init__(self, cert_file, key_file, ca_file=None, require_client_cert=False):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert_file, key_file)
        if require_client_cert:
            self.context.load_verify_locations(ca_file)
            self.context.verify_mode = ssl.CERT_REQUIRED
        self.handshake_completed = False
        self.handshake_error = None
        self.sni_name = None
        self.peer_certificate = None
        self._thread = None
        self._server_socket = None

        def _sni_callback(ssl_socket, hostname, ssl_context):
            self.sni_name = hostname

        self.context.set_servername_callback(_sni_callback)

    def connect(self):
        client_socket, server_socket = socket.socketpair()
        self._server_socket = server_socket
        self._thread = threading.Thread(target=self._handshake)
        self._thread.daemon = True
        self._thread.start()
        return client_socket

    def wait(self, timeout=10):
        if self._thread is not None:
            self._thread.join(timeout)
        self._server_socket.close()

    def _handshake(self):
        try:
            self._server_socket.settimeout(5)
            wrapped = self.context.wrap_socket(self._server_socket, server_side=True)
        except Exception as error:
            self.handshake_error = error
            self._server_socket.close()
            return
        self.handshake_completed = True
        self.peer_certificate = wrapped.getpeercert(binary_form=True)
        wrapped.close()


def create_tls_workspace():
    return tempfile.mkdtemp(prefix='ldap3-tls-')


def remove_tls_workspace(directory):
    shutil.rmtree(directory, ignore_errors=True)
