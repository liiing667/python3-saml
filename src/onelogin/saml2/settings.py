# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Settings class

Copyright (c) 2010-2021 OneLogin, Inc.
MIT License

Setting class of OneLogin's Python Toolkit.

"""
import base64
import hashlib
import re
from copy import deepcopy
from time import time
from os.path import commonpath, dirname, exists, isabs, join, realpath, sep
from urllib.parse import urlsplit

from onelogin.saml2 import compat
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

try:
    import ujson as json
except ImportError:
    import json

try:
    basestring
except NameError:
    basestring = str

# Regex from Django Software Foundation and individual contributors.
# Released under a BSD 3-Clause License
url_regex = re.compile(
    r'^(?:[a-z0-9\.\-]*)://'  # scheme is validated separately
    r'(?:(?:[A-Z0-9_](?:[A-Z0-9-_]{0,61}[A-Z0-9_])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
url_regex_single_label_domain = re.compile(
    r'^(?:[a-z0-9\.\-]*)://'  # scheme is validated separately
    r'(?:(?:[A-Z0-9_](?:[A-Z0-9-_]{0,61}[A-Z0-9_])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'(?:[A-Z0-9_](?:[A-Z0-9-_]{0,61}[A-Z0-9_]))|'  # single-label-domain
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
url_schemes = ['http', 'https', 'ftp', 'ftps']


def validate_url(url, allow_single_label_domain=False):
    """
    Auxiliary method to validate an urllib
    :param url: An url to be validated
    :type url: string
    :param allow_single_label_domain: In order to allow or not single label domain
    :type url: bool
    :returns: True if the url is valid
    :rtype: bool
    """

    scheme = url.split('://')[0].lower()
    if scheme not in url_schemes:
        return False
    if allow_single_label_domain:
        if not bool(url_regex_single_label_domain.search(url)):
            return False
    else:
        if not bool(url_regex.search(url)):
            return False
    return True


class OneLogin_Saml2_Settings(object):
    """

    Handles the settings of the Python toolkits.

    """

    metadata_class = OneLogin_Saml2_Metadata

    def __init__(self, settings=None, custom_base_path=None, sp_validation_only=False):
        """
        Initializes the settings:
        - Sets the paths of the different folders
        - Loads settings info from settings file or array/object provided

        :param settings: SAML Toolkit Settings
        :type settings: dict

        :param custom_base_path: Path where are stored the settings file and the cert folder
        :type custom_base_path: string

        :param sp_validation_only: Avoid the IdP validation
        :type sp_validation_only: boolean
        """
        self._sp_validation_only = sp_validation_only
        self._paths = {}
        self._strict = True
        self._debug = False
        self._sp = {}
        self._idp = {}
        self._security = {}
        self._contacts = {}
        self._organization = {}
        self._errors = []
        self._validated_sp = {}
        self._validated_idp = {}

        self._load_paths(base_path=custom_base_path)
        self._update_paths(settings)

        if settings is None:
            try:
                valid = self._load_settings_from_file()
            except Exception as e:
                raise e
            if not valid:
                raise OneLogin_Saml2_Error(
                    'Invalid dict settings at the file: %s',
                    OneLogin_Saml2_Error.SETTINGS_INVALID,
                    ','.join(self._errors)
                )
        elif isinstance(settings, dict):
            if not self._load_settings_from_dict(settings):
                raise OneLogin_Saml2_Error(
                    'Invalid dict settings: %s',
                    OneLogin_Saml2_Error.SETTINGS_INVALID,
                    ','.join(self._errors)
                )
        else:
            raise OneLogin_Saml2_Error(
                'Unsupported settings object',
                OneLogin_Saml2_Error.UNSUPPORTED_SETTINGS_OBJECT
            )

        self.format_idp_cert()
        if 'x509certMulti' in self._idp:
            self.format_idp_cert_multi()
        self.format_sp_cert()
        if 'x509certNew' in self._sp:
            self.format_sp_cert_new()
        self.format_sp_key()
        self._publish_validated_state()

    def _load_paths(self, base_path=None):
        """
        Set the paths of the different folders
        """
        if base_path is None:
            base_path = dirname(dirname(dirname(__file__)))
        if not base_path.endswith(sep):
            base_path += sep
        self._paths = {
            'base': base_path,
            'cert': base_path + 'certs' + sep,
            'lib': dirname(__file__) + sep
        }

    def _update_paths(self, settings):
        """
        Set custom paths if necessary
        """
        if not isinstance(settings, dict):
            return

        if 'custom_base_path' in settings:
            base_path = settings['custom_base_path']
            base_path = join(dirname(__file__), base_path)
            self._load_paths(base_path)

    def _resolve_cert_filename(self, filename):
        """
        Resolve a certificate or key filename inside the configured cert
        directory.

        Settings may only refer to files that belong to the deployment they
        describe.  Absolute paths, NUL bytes, ``..`` traversal and symlinks
        pointing outside of the cert directory are therefore rejected.

        :param filename: Certificate or key filename from the settings
        :type filename: string

        :returns: The resolved path, or None if the filename is not safe
        :rtype: string or None
        """
        if not isinstance(filename, basestring) or not filename or "\x00" in filename:
            return None
        if isabs(filename):
            return None

        cert_path = self.get_cert_path()
        if not isinstance(cert_path, basestring) or not cert_path:
            return None

        try:
            cert_dir = realpath(cert_path)
            resolved = realpath(join(cert_dir, filename))
            if commonpath([cert_dir, resolved]) != cert_dir:
                return None
        except (OSError, TypeError, ValueError):
            return None
        return resolved

    def _read_cert_file(self, filename):
        """
        Read a certificate or key file after checking that it belongs to the
        current deployment.

        :returns: The file contents, or None when the file can not be used
        :rtype: string or None
        """
        file_path = self._resolve_cert_filename(filename)
        if file_path is None:
            return None
        try:
            with open(file_path, 'r') as cert_file:
                return cert_file.read()
        except (IOError, OSError):
            return None

    @staticmethod
    def _decode_pem_or_base64(data):
        """
        Decode PEM or raw base64 data into DER bytes.

        The PEM header is deliberately not inspected: some deployments use
        non-standard headers and the toolkit historically accepted the base64
        payload as long as it was a valid certificate or key.
        """
        if not isinstance(data, basestring) or not data.strip():
            return None

        payload = []
        for line in data.replace("\r", "").split("\n"):
            line = line.strip()
            if not line or line.startswith("-----"):
                continue
            payload.append(line.replace(" ", ""))

        try:
            return base64.b64decode("".join(payload), validate=False)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _get_url_host(url):
        """
        Return the lower-cased hostname of an absolute URL, or None when the
        value is not an URL with a host (for example a URN entityID).
        """
        if not isinstance(url, basestring) or not url:
            return None
        try:
            parsed = urlsplit(url)
        except (TypeError, ValueError):
            return None
        if not parsed.scheme or not parsed.hostname:
            return None
        return parsed.hostname.lower().rstrip(".")

    @classmethod
    def _entity_matches_endpoints(cls, entity_id, endpoints):
        """
        Check that every absolute endpoint URL belongs to the same host as the
        entityID that defines the deployment.

        Non-URL entityIDs (URN values are common in SAML) do not carry a host,
        so they can not be bound this way and keep their historical behavior.
        """
        entity_host = cls._get_url_host(entity_id)
        if entity_host is None:
            return True

        for endpoint in endpoints:
            if not endpoint:
                continue
            endpoint_host = cls._get_url_host(endpoint)
            if endpoint_host is not None and endpoint_host != entity_host:
                return False
        return True

    @classmethod
    def _certificate_fingerprint(cls, certificate, algorithm):
        """
        Calculate a certificate fingerprint from PEM or raw base64 input.
        """
        if not isinstance(algorithm, basestring):
            return None
        der = certificate if isinstance(certificate, bytes) else cls._decode_pem_or_base64(certificate)
        if not der:
            return None
        try:
            return hashlib.new(algorithm.lower(), der).hexdigest()
        except (ValueError, TypeError):
            return None

    @classmethod
    def _parse_certificate(cls, data):
        """
        Parse a certificate.

        :returns: A certificate object when cryptography is available, False
            when the data is not a certificate, and None when parsing is not
            available.
        """
        der = data if isinstance(data, bytes) else cls._decode_pem_or_base64(data)
        if not der:
            return False

        try:
            from cryptography import x509
        except ImportError:
            try:
                import xmlsec
                xmlsec.Key.from_memory(der, xmlsec.KeyFormat.CERT_DER, None)
                return der
            except Exception:
                return False
        try:
            return x509.load_der_x509_certificate(der)
        except Exception:
            return False

    @classmethod
    def _parse_private_key(cls, data):
        """
        Parse an unencrypted private key.

        :returns: A private key object when cryptography is available, False
            when the data is not a private key, and None when parsing is not
            available.
        """
        der = data if isinstance(data, bytes) else cls._decode_pem_or_base64(data)
        if not der:
            return False

        try:
            from cryptography.hazmat.primitives.serialization import load_der_private_key
        except ImportError:
            try:
                import xmlsec
                xmlsec.Key.from_memory(der, xmlsec.KeyFormat.DER, None)
                return der
            except Exception:
                return False
        try:
            return load_der_private_key(der, password=None)
        except Exception:
            return False

    @staticmethod
    def _xmlsec_private_key_matches_certificate(private_key, certificate):
        """
        Verify a key/certificate pair with xmlsec when cryptography is not
        installed.  This keeps the identity check fail-closed without adding a
        new mandatory dependency.
        """
        try:
            import xmlsec
            key_data = private_key if isinstance(private_key, bytes) else OneLogin_Saml2_Settings._decode_pem_or_base64(private_key)
            cert_data = certificate if isinstance(certificate, bytes) else OneLogin_Saml2_Settings._decode_pem_or_base64(certificate)
            if not key_data or not cert_data:
                return False
            key = xmlsec.Key.from_memory(key_data, xmlsec.KeyFormat.DER, None)
            cert = xmlsec.Key.from_memory(cert_data, xmlsec.KeyFormat.CERT_DER, None)
            payload = b"onelogin-saml-settings-deployment-identity"
            for transform in (
                xmlsec.Transform.RSA_SHA256,
                xmlsec.Transform.RSA_SHA1,
                xmlsec.Transform.ECDSA_SHA256,
                xmlsec.Transform.DSA_SHA1,
            ):
                try:
                    sign_context = xmlsec.SignatureContext()
                    sign_context.key = key
                    signature = sign_context.sign_binary(payload, transform)
                    verify_context = xmlsec.SignatureContext()
                    verify_context.key = cert
                    verify_context.verify_binary(payload, transform, signature)
                    return True
                except Exception:
                    continue
            return False
        except Exception:
            return False

    @classmethod
    def _certificates_match(cls, first, second):
        """
        Check whether two certificate representations identify the same
        certificate.
        """
        first_cert = cls._parse_certificate(first)
        second_cert = cls._parse_certificate(second)

        if first_cert is not None and second_cert is not None:
            if first_cert is False or second_cert is False:
                return False
            if isinstance(first_cert, bytes) and isinstance(second_cert, bytes):
                return first_cert == second_cert
            from cryptography.hazmat.primitives.serialization import Encoding
            return first_cert.public_bytes(Encoding.DER) == second_cert.public_bytes(Encoding.DER)

        # cryptography is unavailable.  Compare the DER payload, which is the
        # best deployment-local check that can be made without new runtime
        # dependencies.
        first_der = first if isinstance(first, bytes) else cls._decode_pem_or_base64(first)
        second_der = second if isinstance(second, bytes) else cls._decode_pem_or_base64(second)
        return first_der is not None and first_der == second_der

    @classmethod
    def _private_key_matches_certificate(cls, private_key, certificate):
        """
        Check that a private key and a certificate belong to the same key pair.
        """
        key = cls._parse_private_key(private_key)
        cert = cls._parse_certificate(certificate)
        if key is None or cert is None:
            # No parser available; do not reject otherwise valid legacy
            # configurations because of an optional dependency.
            return True
        if key is False or cert is False:
            return False
        if isinstance(key, bytes) and isinstance(cert, bytes):
            return cls._xmlsec_private_key_matches_certificate(private_key, certificate)

        from cryptography.hazmat.primitives import serialization

        key_public = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_public = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return key_public == cert_public

    @classmethod
    def _private_keys_match(cls, first, second):
        """
        Check whether two private key representations identify the same key.
        """
        first_key = cls._parse_private_key(first)
        second_key = cls._parse_private_key(second)
        if first_key is None or second_key is None:
            return True
        if first_key is False or second_key is False:
            return False
        if isinstance(first_key, bytes) and isinstance(second_key, bytes):
            # xmlsec does not expose the public key derived from a private
            # key, so the pair itself is checked against the certificate
            # elsewhere when that is possible.
            return True

        from cryptography.hazmat.primitives import serialization

        first_public = first_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        second_public = second_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return first_public == second_public

    def get_base_path(self):
        """
        Returns base path

        :return: The base toolkit folder path
        :rtype: string
        """
        return self._paths['base']

    def get_cert_path(self):
        """
        Returns cert path

        :return: The cert folder path
        :rtype: string
        """
        return self._paths['cert']

    def set_cert_path(self, path):
        """
        Set a new cert path
        """
        self._paths['cert'] = path

    def set_sp_cert_filename(self, filename):
        """
        Set the filename of the SP certificate
        """
        if self._resolve_cert_filename(filename) is None:
            raise OneLogin_Saml2_Error(
                'Invalid SP certificate filename',
                OneLogin_Saml2_Error.SETTINGS_INVALID
            )
        self._sp['cert_filename'] = filename

    def set_sp_key_filename(self, filename):
        """
        Set the filename of the SP key
        """
        if self._resolve_cert_filename(filename) is None:
            raise OneLogin_Saml2_Error(
                'Invalid SP key filename',
                OneLogin_Saml2_Error.SETTINGS_INVALID
            )
        self._sp['key_filename'] = filename

    def set_idp_cert_filename(self, filename):
        """
        Set the filename of the idp certificate
        """
        if self._resolve_cert_filename(filename) is None:
            raise OneLogin_Saml2_Error(
                'Invalid IdP certificate filename',
                OneLogin_Saml2_Error.SETTINGS_INVALID
            )
        self._idp['cert_filename'] = filename

    def get_lib_path(self):
        """
        Returns lib path

        :return: The library folder path
        :rtype: string
        """
        return self._paths['lib']

    def get_schemas_path(self):
        """
        Returns schema path

        :return: The schema folder path
        :rtype: string
        """
        return self._paths['lib'] + 'schemas/'

    def _load_settings_from_dict(self, settings):
        """
        Loads settings info from a settings Dict, adds default values and validates the settings

        :param settings: SAML Toolkit Settings
        :type settings: dict

        :returns: True if the settings info is valid
        :rtype: boolean
        """
        previous_state = {
            'sp': deepcopy(self._sp),
            'idp': deepcopy(self._idp),
            'strict': self._strict,
            'debug': self._debug,
            'security': deepcopy(self._security),
            'contacts': deepcopy(self._contacts),
            'organization': deepcopy(self._organization),
            'validated_sp': deepcopy(self._validated_sp),
            'validated_idp': deepcopy(self._validated_idp),
        }

        self._sp = settings.get('sp', {})
        self._idp = settings.get('idp', {})
        self._strict = settings.get('strict', True)
        self._debug = settings.get('debug', False)
        self._security = settings.get('security', {})
        self._contacts = settings.get('contactPerson', {})
        self._organization = settings.get('organization', {})
        self._add_default_values()

        self._errors = []
        errors = self.check_settings(settings)

        if len(errors) == 0:
            self._publish_validated_state()
            return True

        # A failed update must not publish a partial configuration or leave a
        # mixture of the new input and the previous deployment's state.
        self._sp = previous_state['sp']
        self._idp = previous_state['idp']
        self._strict = previous_state['strict']
        self._debug = previous_state['debug']
        self._security = previous_state['security']
        self._contacts = previous_state['contacts']
        self._organization = previous_state['organization']
        self._validated_sp = previous_state['validated_sp']
        self._validated_idp = previous_state['validated_idp']

        self._errors = errors
        return False

    def _publish_validated_state(self):
        """
        Keep an immutable snapshot of the configuration that passed
        validation.  Consumers read this generation instead of a settings
        dictionary that the caller may keep mutating.
        """
        self._validated_sp = deepcopy(self._sp)
        self._validated_idp = deepcopy(self._idp)

    def _load_settings_from_file(self):
        """
        Loads settings info from the settings json file

        :returns: True if the settings info is valid
        :rtype: boolean
        """
        filename = self.get_base_path() + 'settings.json'

        if not exists(filename):
            raise OneLogin_Saml2_Error(
                'Settings file not found: %s',
                OneLogin_Saml2_Error.SETTINGS_FILE_NOT_FOUND,
                filename
            )

        # In the php toolkit instead of being a json file it is a php file and
        # it is directly included
        with open(filename, 'r') as json_data:
            settings = json.loads(json_data.read())

        advanced_filename = self.get_base_path() + 'advanced_settings.json'
        if exists(advanced_filename):
            with open(advanced_filename, 'r') as json_data:
                settings.update(json.loads(json_data.read()))  # Merge settings

        return self._load_settings_from_dict(settings)

    def _add_default_values(self):
        """
        Add default values if the settings info is not complete
        """
        self._sp.setdefault('assertionConsumerService', {})
        self._sp['assertionConsumerService'].setdefault('binding', OneLogin_Saml2_Constants.BINDING_HTTP_POST)

        self._sp.setdefault('attributeConsumingService', {})

        self._sp.setdefault('singleLogoutService', {})
        self._sp['singleLogoutService'].setdefault('binding', OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT)

        self._idp.setdefault('singleLogoutService', {})

        # Related to nameID
        self._sp.setdefault('NameIDFormat', OneLogin_Saml2_Constants.NAMEID_UNSPECIFIED)
        self._security.setdefault('nameIdEncrypted', False)

        # Metadata format
        self._security.setdefault('metadataValidUntil', None)  # None means use default
        self._security.setdefault('metadataCacheDuration', None)  # None means use default

        # Sign provided
        self._security.setdefault('authnRequestsSigned', False)
        self._security.setdefault('logoutRequestSigned', False)
        self._security.setdefault('logoutResponseSigned', False)
        self._security.setdefault('signMetadata', False)

        # Sign expected
        self._security.setdefault('wantMessagesSigned', False)
        self._security.setdefault('wantAssertionsSigned', False)

        # NameID element expected
        self._security.setdefault('wantNameId', True)

        # Encrypt expected
        self._security.setdefault('wantAssertionsEncrypted', False)
        self._security.setdefault('wantNameIdEncrypted', False)

        # Signature Algorithm
        self._security.setdefault('signatureAlgorithm', OneLogin_Saml2_Constants.RSA_SHA256)

        # Digest Algorithm
        self._security.setdefault('digestAlgorithm', OneLogin_Saml2_Constants.SHA256)

        # Reject Deprecated Algorithms
        self._security.setdefault('rejectDeprecatedAlgorithm', False)

        # AttributeStatement required by default
        self._security.setdefault('wantAttributeStatement', True)

        # Disallow duplicate attribute names by default
        self._security.setdefault('allowRepeatAttributeName', False)

        self._idp.setdefault('x509cert', '')
        self._idp.setdefault('certFingerprint', '')
        self._idp.setdefault('certFingerprintAlgorithm', 'sha1')

        self._sp.setdefault('x509cert', '')
        self._sp.setdefault('privateKey', '')

        # Set the default filenames for the certificates and keys
        self._idp.setdefault('cert_filename', 'idp.crt')
        self._sp.setdefault('cert_filename', 'sp.crt')
        self._sp.setdefault('key_filename', 'sp.key')

        self._security.setdefault('requestedAuthnContext', True)
        self._security.setdefault('requestedAuthnContextComparison', 'exact')
        self._security.setdefault('failOnAuthnContextMismatch', False)

    def check_settings(self, settings):
        """
        Checks the settings info.

        :param settings: Dict with settings data
        :type settings: dict

        :returns: Errors found on the settings data
        :rtype: list
        """
        assert isinstance(settings, dict)

        errors = []
        if not isinstance(settings, dict) or len(settings) == 0:
            errors.append('invalid_syntax')
        else:
            if not self._sp_validation_only:
                errors += self.check_idp_settings(settings)
            sp_errors = self.check_sp_settings(settings)
            errors += sp_errors

        return errors

    def check_idp_settings(self, settings):
        """
        Checks the IdP settings info.
        :param settings: Dict with settings data
        :type settings: dict
        :returns: Errors found on the IdP settings data
        :rtype: list
        """
        assert isinstance(settings, dict)

        errors = []
        if not isinstance(settings, dict) or len(settings) == 0:
            errors.append('invalid_syntax')
        else:
            if not settings.get('idp'):
                errors.append('idp_not_found')
            else:
                allow_single_domain_urls = self._get_allow_single_label_domain(settings)
                check_strict = bool(settings.get('strict', self._strict))
                idp = settings['idp']
                old_idp = self._idp
                self._idp = idp
                if not idp.get('entityId'):
                    errors.append('idp_entityId_not_found')

                if not idp.get('singleSignOnService', {}).get('url'):
                    errors.append('idp_sso_not_found')
                elif not validate_url(idp['singleSignOnService']['url'], allow_single_domain_urls):
                    errors.append('idp_sso_url_invalid')

                slo_url = idp.get('singleLogoutService', {}).get('url')
                if slo_url and not validate_url(slo_url, allow_single_domain_urls):
                    errors.append('idp_slo_url_invalid')

                if check_strict:
                    idp_idp_endpoints = [
                        idp.get('singleSignOnService', {}).get('url'),
                        slo_url,
                        idp.get('singleLogoutService', {}).get('responseUrl'),
                    ]
                    if not self._entity_matches_endpoints(idp.get('entityId'), idp_idp_endpoints):
                        errors.append('idp_entityId_endpoint_mismatch')

                idp_cert_filename = idp.get('cert_filename', 'idp.crt')
                if idp_cert_filename != 'idp.crt':
                    idp_cert_file = self._read_cert_file(idp_cert_filename)
                    if idp_cert_file is None:
                        errors.append('idp_cert_not_found_and_required')
                    else:
                        parsed_cert = self._parse_certificate(idp_cert_file)
                        if parsed_cert is False:
                            errors.append('idp_cert_invalid')
                        elif idp.get('x509cert') and not self._certificates_match(idp['x509cert'], idp_cert_file):
                            errors.append('idp_cert_mismatch')

                fingerprint_cert_is_explicit = bool(idp.get('x509cert')) or idp.get('cert_filename', 'idp.crt') != 'idp.crt'
                if fingerprint_cert_is_explicit and 'x509certMulti' not in idp and idp.get('certFingerprint'):
                    configured_cert = self.get_idp_cert()
                    if configured_cert:
                        fingerprint_alg = idp.get('certFingerprintAlgorithm', 'sha1')
                        expected_fingerprint = re.sub(r'[\s:]', '', idp['certFingerprint']).lower()
                        actual_fingerprint = self._certificate_fingerprint(configured_cert, fingerprint_alg)
                        if actual_fingerprint is not None and actual_fingerprint != expected_fingerprint:
                            errors.append('idp_cert_fingerprint_mismatch')

                if check_strict and idp.get('x509cert'):
                    if self._parse_certificate(idp['x509cert']) is False:
                        errors.append('idp_cert_invalid')

                if 'security' in settings:
                    security = settings['security']

                    exists_x509 = bool(self.get_idp_cert())
                    exists_fingerprint = bool(idp.get('certFingerprint'))

                    exists_multix509sign = 'x509certMulti' in idp and \
                        'signing' in idp['x509certMulti'] and \
                        idp['x509certMulti']['signing']
                    exists_multix509enc = 'x509certMulti' in idp and \
                        'encryption' in idp['x509certMulti'] and \
                        idp['x509certMulti']['encryption']

                    want_assert_sign = bool(security.get('wantAssertionsSigned'))
                    want_mes_signed = bool(security.get('wantMessagesSigned'))
                    nameid_enc = bool(security.get('nameIdEncrypted'))

                    if (want_assert_sign or want_mes_signed) and \
                            not (exists_x509 or exists_fingerprint or exists_multix509sign):
                        errors.append('idp_cert_or_fingerprint_not_found_and_required')
                    if nameid_enc and not (exists_x509 or exists_multix509enc):
                        errors.append('idp_cert_not_found_and_required')
        if 'old_idp' in locals():
            self._idp = old_idp
        return errors

    def check_sp_settings(self, settings):
        """
        Checks the SP settings info.
        :param settings: Dict with settings data
        :type settings: dict
        :returns: Errors found on the SP settings data
        :rtype: list
        """
        assert isinstance(settings, dict)

        errors = []
        if not isinstance(settings, dict) or not settings:
            errors.append('invalid_syntax')
        else:
            if not settings.get('sp'):
                errors.append('sp_not_found')
            else:
                allow_single_domain_urls = self._get_allow_single_label_domain(settings)
                sp = settings['sp']
                old_sp = self._sp
                self._sp = sp
                security = settings.get('security', {})
                check_strict = bool(settings.get('strict', self._strict))

                if not sp.get('entityId'):
                    errors.append('sp_entityId_not_found')

                if not sp.get('assertionConsumerService', {}).get('url'):
                    errors.append('sp_acs_not_found')
                elif not validate_url(sp['assertionConsumerService']['url'], allow_single_domain_urls):
                    errors.append('sp_acs_url_invalid')

                if sp.get('attributeConsumingService'):
                    attributeConsumingService = sp['attributeConsumingService']
                    if 'serviceName' not in attributeConsumingService:
                        errors.append('sp_attributeConsumingService_serviceName_not_found')
                    elif not isinstance(attributeConsumingService['serviceName'], basestring):
                        errors.append('sp_attributeConsumingService_serviceName_type_invalid')

                    if 'requestedAttributes' not in attributeConsumingService:
                        errors.append('sp_attributeConsumingService_requestedAttributes_not_found')
                    elif not isinstance(attributeConsumingService['requestedAttributes'], list):
                        errors.append('sp_attributeConsumingService_serviceName_type_invalid')
                    else:
                        for req_attrib in attributeConsumingService['requestedAttributes']:
                            if 'name' not in req_attrib:
                                errors.append('sp_attributeConsumingService_requestedAttributes_name_not_found')
                            if 'name' in req_attrib and not req_attrib['name'].strip():
                                errors.append('sp_attributeConsumingService_requestedAttributes_name_invalid')
                            if 'attributeValue' in req_attrib and type(req_attrib['attributeValue']) != list:
                                errors.append('sp_attributeConsumingService_requestedAttributes_attributeValue_type_invalid')
                            if 'isRequired' in req_attrib and type(req_attrib['isRequired']) != bool:
                                errors.append('sp_attributeConsumingService_requestedAttributes_isRequired_type_invalid')

                    if "serviceDescription" in attributeConsumingService and not isinstance(attributeConsumingService['serviceDescription'], basestring):
                        errors.append('sp_attributeConsumingService_serviceDescription_type_invalid')

                slo_url = sp.get('singleLogoutService', {}).get('url')
                if slo_url and not validate_url(slo_url, allow_single_domain_urls):
                    errors.append('sp_sls_url_invalid')

                if check_strict:
                    sp_endpoints = [
                        sp.get('assertionConsumerService', {}).get('url'),
                        slo_url,
                        sp.get('singleLogoutService', {}).get('responseUrl'),
                    ]
                    if not self._entity_matches_endpoints(sp.get('entityId'), sp_endpoints):
                        errors.append('sp_entityId_endpoint_mismatch')

                sp_cert_file = None
                sp_key_file = None

                sp_cert_filename = sp.get('cert_filename', 'sp.crt')
                if sp_cert_filename != 'sp.crt':
                    sp_cert_file = self._read_cert_file(sp_cert_filename)
                    if sp_cert_file is None:
                        errors.append('sp_cert_not_found_and_required')
                    else:
                        parsed_cert = self._parse_certificate(sp_cert_file)
                        if parsed_cert is False:
                            errors.append('sp_cert_invalid')
                        elif sp.get('x509cert') and not self._certificates_match(sp['x509cert'], sp_cert_file):
                            errors.append('sp_cert_mismatch')

                sp_key_filename = sp.get('key_filename', 'sp.key')
                if sp_key_filename != 'sp.key':
                    sp_key_file = self._read_cert_file(sp_key_filename)
                    if sp_key_file is None:
                        errors.append('sp_cert_not_found_and_required')
                    else:
                        parsed_key = self._parse_private_key(sp_key_file)
                        if parsed_key is False:
                            errors.append('sp_private_key_invalid')
                        elif sp.get('privateKey') and not self._private_keys_match(sp['privateKey'], sp_key_file):
                            errors.append('sp_key_mismatch')

                cert_source_explicit = bool(sp.get('x509cert')) or sp.get('cert_filename', 'sp.crt') != 'sp.crt'
                key_source_explicit = bool(sp.get('privateKey')) or sp.get('key_filename', 'sp.key') != 'sp.key'
                custom_filename = sp.get('cert_filename', 'sp.crt') != 'sp.crt' or \
                    sp.get('key_filename', 'sp.key') != 'sp.key'
                if (cert_source_explicit and key_source_explicit) or custom_filename:
                    sp_cert = self.get_sp_cert()
                    sp_key = self.get_sp_key()
                    if sp_cert and sp_key and not self._private_key_matches_certificate(sp_key, sp_cert):
                        errors.append('sp_cert_key_mismatch')
                elif check_strict:
                    sp_cert = self.get_sp_cert()
                    sp_key = self.get_sp_key()
                    if sp_cert and sp_key and not self._private_key_matches_certificate(sp_key, sp_cert):
                        errors.append('sp_cert_key_mismatch')

                if check_strict:
                    if sp.get('x509cert') and self._parse_certificate(sp['x509cert']) is False:
                        errors.append('sp_cert_invalid')
                    if sp.get('privateKey') and self._parse_private_key(sp['privateKey']) is False:
                        errors.append('sp_private_key_invalid')

                if 'signMetadata' in security and isinstance(security['signMetadata'], dict):
                    if 'keyFileName' not in security['signMetadata'] or \
                            'certFileName' not in security['signMetadata']:
                        errors.append('sp_signMetadata_invalid')

                authn_sign = bool(security.get('authnRequestsSigned'))
                logout_req_sign = bool(security.get('logoutRequestSigned'))
                logout_res_sign = bool(security.get('logoutResponseSigned'))
                want_assert_enc = bool(security.get('wantAssertionsEncrypted'))
                want_nameid_enc = bool(security.get('wantNameIdEncrypted'))

                if not self.check_sp_certs():
                    if authn_sign or logout_req_sign or logout_res_sign or \
                       want_assert_enc or want_nameid_enc:
                        errors.append('sp_cert_not_found_and_required')

            if 'contactPerson' in settings:
                types = settings['contactPerson']
                valid_types = ['technical', 'support', 'administrative', 'billing', 'other']
                for c_type in types:
                    if c_type not in valid_types:
                        errors.append('contact_type_invalid')
                        break

                for c_type in settings['contactPerson']:
                    contact = settings['contactPerson'][c_type]
                    if ('givenName' not in contact or len(contact['givenName']) == 0) or \
                            ('emailAddress' not in contact or len(contact['emailAddress']) == 0):
                        errors.append('contact_not_enought_data')
                        break

            if 'organization' in settings:
                for org in settings['organization']:
                    organization = settings['organization'][org]
                    if ('name' not in organization or len(organization['name']) == 0) or \
                        ('displayname' not in organization or len(organization['displayname']) == 0) or \
                            ('url' not in organization or len(organization['url']) == 0):
                        errors.append('organization_not_enought_data')
                        break
        if 'old_sp' in locals():
            self._sp = old_sp
        return errors

    def check_sp_certs(self):
        """
        Checks if the x509 certs of the SP exists and are valid.
        :returns: If the x509 certs of the SP exists and are valid
        :rtype: boolean
        """
        key = self.get_sp_key()
        cert = self.get_sp_cert()
        return key is not None and cert is not None

    def get_idp_sso_url(self):
        """
        Gets the IdP SSO URL.

        :returns: An URL, the SSO endpoint of the IdP
        :rtype: string
        """
        idp_data = self.get_idp_data()
        return idp_data['singleSignOnService']['url']

    def get_idp_slo_url(self):
        """
        Gets the IdP SLO URL.

        :returns: An URL, the SLO endpoint of the IdP
        :rtype: string
        """
        idp_data = self.get_idp_data()
        if 'url' in idp_data['singleLogoutService']:
            return idp_data['singleLogoutService']['url']

    def get_idp_slo_response_url(self):
        """
        Gets the IdP SLO return URL for IdP-initiated logout.

        :returns: an URL, the SLO return endpoint of the IdP
        :rtype: string
        """
        idp_data = self.get_idp_data()
        if 'url' in idp_data['singleLogoutService']:
            return idp_data['singleLogoutService'].get('responseUrl', self.get_idp_slo_url())

    def get_sp_key(self):
        """
        Returns the x509 private key of the SP.
        :returns: SP private key
        :rtype: string or None
        """
        key = self._sp.get('privateKey')
        key_file_name = self._resolve_cert_filename(self._sp.get('key_filename', 'sp.key'))

        if not key and key_file_name and exists(key_file_name):
            with open(key_file_name) as f:
                key = f.read()

        return key or None

    def get_sp_cert(self):
        """
        Returns the x509 public cert of the SP.
        :returns: SP public cert
        :rtype: string or None
        """
        cert = self._sp.get('x509cert')
        cert_file_name = self._resolve_cert_filename(self._sp.get('cert_filename', 'sp.crt'))

        if not cert and cert_file_name and exists(cert_file_name):
            with open(cert_file_name) as f:
                cert = f.read()

        return cert or None

    def get_sp_cert_new(self):
        """
        Returns the x509 public of the SP planned
        to be used soon instead the other public cert
        :returns: SP public cert new
        :rtype: string or None
        """
        cert = self._sp.get('x509certNew')
        cert_file_name = self._resolve_cert_filename('sp_new.crt')

        if not cert and cert_file_name and exists(cert_file_name):
            with open(cert_file_name) as f:
                cert = f.read()

        return cert or None

    def get_idp_cert(self):
        """
        Returns the x509 public cert of the IdP.
        :returns: IdP public cert
        :rtype: string
        """
        cert = self._idp.get('x509cert')
        cert_file_name = self._resolve_cert_filename(self._idp.get('cert_filename', 'idp.crt'))
        if not cert and cert_file_name and exists(cert_file_name):
            with open(cert_file_name) as f:
                cert = f.read()
        return cert or None

    def get_idp_data(self):
        """
        Gets the IdP data.

        :returns: IdP info
        :rtype: dict
        """
        return deepcopy(self._validated_idp) if self._validated_idp else deepcopy(self._idp)

    def get_sp_data(self):
        """
        Gets the SP data.

        :returns: SP info
        :rtype: dict
        """
        return deepcopy(self._validated_sp) if self._validated_sp else deepcopy(self._sp)

    def get_security_data(self):
        """
        Gets security data.

        :returns: Security info
        :rtype: dict
        """
        return self._security

    def get_contacts(self):
        """
        Gets contact data.

        :returns: Contacts info
        :rtype: dict
        """
        return self._contacts

    def get_organization(self):
        """
        Gets organization data.

        :returns: Organization info
        :rtype: dict
        """
        return self._organization

    def get_sp_metadata(self):
        """
        Gets the SP metadata. The XML representation.
        :returns: SP metadata (xml)
        :rtype: string
        """
        metadata = self.metadata_class.builder(
            self._sp, self._security['authnRequestsSigned'],
            self._security['wantAssertionsSigned'],
            self._security['metadataValidUntil'],
            self._security['metadataCacheDuration'],
            self.get_contacts(), self.get_organization()
        )

        add_encryption = self._security['wantNameIdEncrypted'] or self._security['wantAssertionsEncrypted']

        cert_new = self.get_sp_cert_new()
        metadata = self.metadata_class.add_x509_key_descriptors(metadata, cert_new, add_encryption)

        cert = self.get_sp_cert()
        metadata = self.metadata_class.add_x509_key_descriptors(metadata, cert, add_encryption)

        # Sign metadata
        if 'signMetadata' in self._security and self._security['signMetadata'] is not False:
            if self._security['signMetadata'] is True:
                # Use the SP's normal key to sign the metadata:
                if not cert:
                    raise OneLogin_Saml2_Error(
                        'Cannot sign metadata: missing SP public key certificate.',
                        OneLogin_Saml2_Error.PUBLIC_CERT_FILE_NOT_FOUND
                    )
                cert_metadata = cert
                key_metadata = self.get_sp_key()
                if not key_metadata:
                    raise OneLogin_Saml2_Error(
                        'Cannot sign metadata: missing SP private key.',
                        OneLogin_Saml2_Error.PRIVATE_KEY_FILE_NOT_FOUND
                    )
            else:
                # Use a custom key to sign the metadata:
                if ('keyFileName' not in self._security['signMetadata'] or
                        'certFileName' not in self._security['signMetadata']):
                    raise OneLogin_Saml2_Error(
                        'Invalid Setting: signMetadata value of the sp is not valid',
                        OneLogin_Saml2_Error.SETTINGS_INVALID_SYNTAX
                    )
                key_file_name = self._security['signMetadata']['keyFileName']
                cert_file_name = self._security['signMetadata']['certFileName']
                key_metadata_file = self._resolve_cert_filename(key_file_name)
                cert_metadata_file = self._resolve_cert_filename(cert_file_name)

                try:
                    if key_metadata_file is None:
                        raise IOError("Invalid private key filename")
                    with open(key_metadata_file, 'r') as f_metadata_key:
                        key_metadata = f_metadata_key.read()
                except IOError:
                    raise OneLogin_Saml2_Error(
                        'Private key file not readable: %s',
                        OneLogin_Saml2_Error.PRIVATE_KEY_FILE_NOT_FOUND,
                        key_file_name
                    )

                try:
                    if cert_metadata_file is None:
                        raise IOError("Invalid certificate filename")
                    with open(cert_metadata_file, 'r') as f_metadata_cert:
                        cert_metadata = f_metadata_cert.read()
                except IOError:
                    raise OneLogin_Saml2_Error(
                        'Public cert file not readable: %s',
                        OneLogin_Saml2_Error.PUBLIC_CERT_FILE_NOT_FOUND,
                        cert_file_name
                    )

            signature_algorithm = self._security['signatureAlgorithm']
            digest_algorithm = self._security['digestAlgorithm']

            metadata = self.metadata_class.sign_metadata(metadata, key_metadata, cert_metadata, signature_algorithm, digest_algorithm)

        return metadata

    def validate_metadata(self, xml):
        """
        Validates an XML SP Metadata.

        :param xml: Metadata's XML that will be validate
        :type xml: string

        :returns: The list of found errors
        :rtype: list
        """

        assert isinstance(xml, compat.text_types)

        if len(xml) == 0:
            raise Exception('Empty string supplied as input')

        errors = []
        root = OneLogin_Saml2_XML.validate_xml(xml, 'saml-schema-metadata-2.0.xsd', self._debug)
        if isinstance(root, str):
            errors.append(root)
        else:
            if root.tag != '{%s}EntityDescriptor' % OneLogin_Saml2_Constants.NS_MD:
                errors.append('noEntityDescriptor_xml')
            else:
                if (len(root.findall('.//md:SPSSODescriptor', namespaces=OneLogin_Saml2_Constants.NSMAP))) != 1:
                    errors.append('onlySPSSODescriptor_allowed_xml')
                else:
                    valid_until, cache_duration = root.get('validUntil'), root.get('cacheDuration')

                    if valid_until:
                        valid_until = OneLogin_Saml2_Utils.parse_SAML_to_time(valid_until)
                    expire_time = OneLogin_Saml2_Utils.get_expire_time(cache_duration, valid_until)
                    if expire_time is not None and int(time()) > int(expire_time):
                        errors.append('expired_xml')

        # TODO: Validate Sign

        return errors

    def format_idp_cert(self):
        """
        Formats the IdP cert.
        """
        self._idp['x509cert'] = OneLogin_Saml2_Utils.format_cert(self._idp['x509cert'])

    def format_idp_cert_multi(self):
        """
        Formats the Multple IdP certs.
        """
        if 'x509certMulti' in self._idp:
            if 'signing' in self._idp['x509certMulti']:
                for idx in range(len(self._idp['x509certMulti']['signing'])):
                    self._idp['x509certMulti']['signing'][idx] = OneLogin_Saml2_Utils.format_cert(self._idp['x509certMulti']['signing'][idx])

            if 'encryption' in self._idp['x509certMulti']:
                for idx in range(len(self._idp['x509certMulti']['encryption'])):
                    self._idp['x509certMulti']['encryption'][idx] = OneLogin_Saml2_Utils.format_cert(self._idp['x509certMulti']['encryption'][idx])

    def format_sp_cert(self):
        """
        Formats the SP cert.
        """
        self._sp['x509cert'] = OneLogin_Saml2_Utils.format_cert(self._sp['x509cert'])

    def format_sp_cert_new(self):
        """
        Formats the SP cert.
        """
        self._sp['x509certNew'] = OneLogin_Saml2_Utils.format_cert(self._sp['x509certNew'])

    def format_sp_key(self):
        """
        Formats the private key.
        """
        self._sp['privateKey'] = OneLogin_Saml2_Utils.format_private_key(self._sp['privateKey'])

    def get_errors(self):
        """
        Returns an array with the errors, the array is empty when the settings is ok.

        :returns: Errors
        :rtype: list
        """
        return self._errors

    def set_strict(self, value):
        """
        Activates or deactivates the strict mode.

        :param value: Strict parameter
        :type value: boolean
        """
        assert isinstance(value, bool)

        self._strict = value

    def is_strict(self):
        """
        Returns if the 'strict' mode is active.

        :returns: Strict parameter
        :rtype: boolean
        """
        return self._strict

    def is_debug_active(self):
        """
        Returns if the debug is active.

        :returns: Debug parameter
        :rtype: boolean
        """
        return self._debug

    def _get_allow_single_label_domain(self, settings):
        security = settings.get('security', {})
        return 'allowSingleLabelDomains' in security.keys() and security['allowSingleLabelDomains']
