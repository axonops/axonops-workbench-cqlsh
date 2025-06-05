# Custom module to check TLS/SSL security configuration and certificates
#
# SECURITY NOTE: This module is a security scanning tool that intentionally connects
# to servers using weak TLS versions and ciphers to detect security vulnerabilities.
# The use of insecure SSL/TLS settings is deliberate and necessary for the tool's
# functionality. This is NOT a security vulnerability.
#
# CodeQL and other security scanners may flag this as allowing insecure TLS versions.
# This is expected and should be marked as a false positive.

import ssl
import socket
import json
import tempfile
from os import path
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
import traceback


# Weak/deprecated cipher suites
WEAK_CIPHERS = [
    'NULL', 'EXPORT', 'DES', 'RC4', '3DES', 'MD5', 'anon',
    'ECDHE-RSA-DES-CBC3-SHA', 'ECDHE-ECDSA-DES-CBC3-SHA',
    'EDH-RSA-DES-CBC3-SHA', 'EDH-DSS-DES-CBC3-SHA',
    'DH-RSA-DES-CBC3-SHA', 'DH-DSS-DES-CBC3-SHA',
    'ADH-DES-CBC3-SHA', 'ADH-RC4-MD5'
]

# Strong cipher suites (supporting PFS)
PFS_CIPHERS = ['ECDHE', 'DHE']

# Minimum recommended key sizes
MIN_RSA_KEY_SIZE = 2048
MIN_DSA_KEY_SIZE = 2048
MIN_EC_KEY_SIZE = 224

# Certificate expiry warning threshold (days)
CERT_EXPIRY_WARNING_DAYS = 30


def extract_connection_info(session):
    """Extract host and port from the active session"""
    try:
        # Get the cluster connection information
        cluster = session.cluster
        contact_points = cluster.contact_points
        port = cluster.port or 9042  # Default Cassandra native port
        
        # Use the first contact point
        if contact_points:
            host = contact_points[0]
        else:
            # Fallback to getting from active connections
            for host_info in cluster.metadata.all_hosts():
                if host_info.is_up:
                    host = host_info.address
                    break
            else:
                raise Exception("No active hosts found in cluster")
                
        return host, port
    except Exception as e:
        raise Exception(f"Failed to extract connection info: {str(e)}")


def get_certificate_chain(host, port, timeout=10):
    """Connect to the host and retrieve the certificate chain"""
    # SECURITY NOTE: This is a security scanning tool that needs to detect weak TLS versions.
    # We intentionally create a permissive context to test what the server actually supports.
    # This is NOT a security vulnerability - it's required functionality for a security scanner.
    
    # Create SSL context that allows us to connect to servers with various configurations
    try:
        # Try to use PROTOCOL_TLS_CLIENT if available (Python 3.6+)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except AttributeError:
        # Fallback for older Python versions
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    
    # Disable hostname and certificate verification since we're analyzing the certificates
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Try to set minimum version to detect weak TLS (Python 3.7+)
    try:
        if hasattr(ssl, 'TLSVersion'):
            context.minimum_version = ssl.TLSVersion.TLSv1
    except Exception:
        # Fallback for older Python versions - set options to allow weak versions
        # OP_NO_SSLv2 is always set by default, we clear other restrictions
        context.options &= ~ssl.OP_NO_SSLv3
        context.options &= ~ssl.OP_NO_TLSv1
        context.options &= ~ssl.OP_NO_TLSv1_1
        context.options &= ~ssl.OP_NO_TLSv1_2
        if hasattr(ssl, 'OP_NO_TLSv1_3'):
            context.options &= ~ssl.OP_NO_TLSv1_3
    
    # Enable weak ciphers for testing purposes
    try:
        context.set_ciphers('ALL:@SECLEVEL=0')
    except ssl.SSLError:
        # Fallback if @SECLEVEL is not supported
        try:
            context.set_ciphers('ALL')
        except ssl.SSLError:
            # Use default ciphers if 'ALL' fails
            pass
    
    # Get all certificates in the chain
    certificates = []
    connection_info = {
        'host': host,
        'port': port,
        'connected': False
    }
    
    # First, try a plain socket connection to check if port is open
    plain_sock = None
    try:
        plain_sock = socket.create_connection((host, port), timeout=timeout)
        # Port is open, now try TLS
        # Note: wrap_socket takes ownership of the socket, but we need to ensure cleanup
        wrapped_sock = None
        try:
            wrapped_sock = context.wrap_socket(plain_sock, server_hostname=host)
            # Get connection info
            connection_info['connected'] = True
            connection_info['tls_version'] = wrapped_sock.version()
            connection_info['cipher_suite'] = wrapped_sock.cipher()[0] if wrapped_sock.cipher() else None
            connection_info['cipher_bits'] = wrapped_sock.cipher()[2] if wrapped_sock.cipher() and len(wrapped_sock.cipher()) > 2 else None
            
            # Get peer certificate (end entity)
            der_cert = wrapped_sock.getpeercert_bin()
            if der_cert:
                certificates.append(der_cert)
            
            # Note: Python's ssl module doesn't provide easy access to the full chain
            # We only get the peer certificate, not intermediates
            # This is a limitation but sufficient for most security checks
            
        except ssl.SSLError as e:
            error_str = str(e)
            # Common SSL errors that indicate non-TLS service
            if any(indicator in error_str.lower() for indicator in [
                'wrong version number',
                'unknown protocol',
                'https proxy request',
                'http request',
                'inappropriate fallback',
                'sslv3 alert handshake failure',
                'tlsv1 alert protocol version'
            ]):
                connection_info['error_type'] = 'NO_TLS'
                connection_info['error'] = f"Service at {host}:{port} does not appear to be using TLS/SSL"
            else:
                connection_info['error_type'] = 'SSL_ERROR'
                connection_info['ssl_error'] = error_str
        except socket.timeout:
            connection_info['error_type'] = 'TIMEOUT'
            connection_info['error'] = f"TLS handshake timeout with {host}:{port}"
        except Exception as e:
            connection_info['error_type'] = 'TLS_ERROR'
            connection_info['error'] = f"TLS connection error to {host}:{port}: {str(e)}"
        finally:
            # Always close the wrapped socket if it was created
            if wrapped_sock:
                try:
                    wrapped_sock.close()
                except:
                    pass
            # plain_sock is closed by wrap_socket or wrapped_sock.close()
    
    except socket.timeout:
        connection_info['error_type'] = 'CONNECTION_TIMEOUT'
        connection_info['error'] = f"Connection timeout to {host}:{port}"
    except ConnectionRefusedError:
        connection_info['error_type'] = 'CONNECTION_REFUSED'
        connection_info['error'] = f"Connection refused to {host}:{port} - service may be down"
    except socket.gaierror as e:
        connection_info['error_type'] = 'DNS_ERROR'
        connection_info['error'] = f"Cannot resolve hostname '{host}': {str(e)}"
    except Exception as e:
        connection_info['error_type'] = 'CONNECTION_ERROR'
        connection_info['error'] = f"Connection error to {host}:{port}: {str(e)}"
    finally:
        # Only close plain_sock if it wasn't wrapped (i.e., connection failed before TLS)
        if plain_sock and not connection_info.get('connected'):
            try:
                plain_sock.close()
            except:
                pass
    
    return certificates, connection_info


def analyze_certificate(cert_der):
    """Analyze a certificate for security issues"""
    cert_info = {}
    
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception as e:
        return {'error': f"Failed to load certificate: {str(e)}", 'error_type': 'PARSE_ERROR'}
    
    # Extract basic fields with individual error handling
    try:
        cert_info['subject'] = cert.subject.rfc4514_string()
    except Exception as e:
        cert_info['subject'] = f"<error: {str(e)}>"
    
    try:
        cert_info['issuer'] = cert.issuer.rfc4514_string()
    except Exception as e:
        cert_info['issuer'] = f"<error: {str(e)}>"
    
    try:
        cert_info['version'] = cert.version.name
    except Exception:
        cert_info['version'] = 'unknown'
    
    try:
        cert_info['serial_number'] = str(cert.serial_number)
    except Exception:
        cert_info['serial_number'] = 'unknown'
    
    # Handle date fields carefully - some certs have weird date encodings
    try:
        cert_info['not_valid_before'] = cert.not_valid_before_utc.isoformat()
    except AttributeError:
        # Older cryptography versions don't have not_valid_before_utc
        try:
            cert_info['not_valid_before'] = cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat()
        except Exception as e:
            cert_info['not_valid_before'] = f"<error: {str(e)}>"
    
    try:
        cert_info['not_valid_after'] = cert.not_valid_after_utc.isoformat()
    except AttributeError:
        # Older cryptography versions don't have not_valid_after_utc
        try:
            cert_info['not_valid_after'] = cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat()
        except Exception as e:
            cert_info['not_valid_after'] = f"<error: {str(e)}>"
    
    # Signature algorithm - handle missing or weird algorithms
    try:
        if hasattr(cert.signature_algorithm_oid, '_name'):
            cert_info['signature_algorithm'] = cert.signature_algorithm_oid._name
        else:
            cert_info['signature_algorithm'] = str(cert.signature_algorithm_oid)
    except Exception as e:
        cert_info['signature_algorithm'] = f"<error: {str(e)}>"
    
    # Self-signed check
    try:
        cert_info['is_self_signed'] = cert.issuer == cert.subject
    except Exception:
        cert_info['is_self_signed'] = None
    
    # Extract key information with proper error handling
    try:
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            cert_info['key_type'] = 'RSA'
            cert_info['key_size'] = public_key.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            cert_info['key_type'] = 'DSA'
            cert_info['key_size'] = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            cert_info['key_type'] = 'EC'
            try:
                cert_info['key_size'] = public_key.curve.key_size
            except AttributeError:
                # Some EC curves don't have key_size
                cert_info['key_size'] = None
                cert_info['curve_name'] = public_key.curve.name
        else:
            cert_info['key_type'] = type(public_key).__name__
            cert_info['key_size'] = None
    except Exception as e:
        cert_info['key_type'] = f"<error: {str(e)}>"
        cert_info['key_size'] = None
    
    # Extract SANs - handle various SAN types
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = []
        for san in san_ext.value:
            try:
                if isinstance(san, x509.DNSName):
                    sans.append(f"DNS:{san.value}")
                elif isinstance(san, x509.IPAddress):
                    sans.append(f"IP:{san.value}")
                elif isinstance(san, x509.RFC822Name):
                    sans.append(f"Email:{san.value}")
                elif isinstance(san, x509.UniformResourceIdentifier):
                    sans.append(f"URI:{san.value}")
                else:
                    # Handle other SAN types generically
                    sans.append(f"{type(san).__name__}:{str(san)}")
            except Exception:
                # Skip problematic SANs
                continue
        cert_info['subject_alternative_names'] = sans
    except x509.ExtensionNotFound:
        cert_info['subject_alternative_names'] = []
    except Exception as e:
        cert_info['subject_alternative_names'] = [f"<error: {str(e)}>"]
    
    # Extract common name from subject - handle malformed subjects
    cert_info['common_name'] = None
    try:
        for attribute in cert.subject:
            if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                cert_info['common_name'] = attribute.value
                break
    except Exception:
        # If we can't iterate through subject, try to extract from string representation
        try:
            subject_str = str(cert.subject)
            if 'CN=' in subject_str:
                cn_start = subject_str.find('CN=') + 3
                cn_end = subject_str.find(',', cn_start)
                if cn_end == -1:
                    cn_end = subject_str.find('>', cn_start)
                if cn_end != -1:
                    cert_info['common_name'] = subject_str[cn_start:cn_end].strip()
        except:
            pass
    
    # Extract key usage extensions with safe defaults
    try:
        key_usage_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        key_usage = key_usage_ext.value
        cert_info['key_usage'] = {
            'digital_signature': getattr(key_usage, 'digital_signature', False),
            'key_encipherment': getattr(key_usage, 'key_encipherment', False),
            'key_agreement': getattr(key_usage, 'key_agreement', False),
            'key_cert_sign': getattr(key_usage, 'key_cert_sign', False),
            'crl_sign': getattr(key_usage, 'crl_sign', False),
            'critical': key_usage_ext.critical
        }
    except x509.ExtensionNotFound:
        cert_info['key_usage'] = None
    except Exception as e:
        cert_info['key_usage'] = {'error': str(e)}
    
    # Extract extended key usage
    try:
        ext_key_usage_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
        ext_usages = []
        for usage in ext_key_usage_ext.value:
            try:
                if hasattr(usage, '_name'):
                    ext_usages.append(usage._name)
                else:
                    ext_usages.append(str(usage))
            except:
                ext_usages.append('unknown')
        cert_info['extended_key_usage'] = ext_usages
    except x509.ExtensionNotFound:
        cert_info['extended_key_usage'] = []
    except Exception as e:
        cert_info['extended_key_usage'] = [f"<error: {str(e)}>"]
    
    # Calculate fingerprints - these should rarely fail
    try:
        cert_info['fingerprints'] = {}
        try:
            cert_info['fingerprints']['sha256'] = cert.fingerprint(hashes.SHA256()).hex(':')
        except Exception as e:
            cert_info['fingerprints']['sha256'] = f"<error: {str(e)}>"
        
        try:
            cert_info['fingerprints']['sha1'] = cert.fingerprint(hashes.SHA1()).hex(':')
        except Exception as e:
            cert_info['fingerprints']['sha1'] = f"<error: {str(e)}>"
    except Exception:
        cert_info['fingerprints'] = {'error': 'Failed to calculate fingerprints'}
    
    return cert_info


def check_certificate_security(cert_info, connection_info):
    """Check certificate for security issues and generate warnings"""
    warnings = []
    
    # Check if certificate could be parsed at all
    if 'error' in cert_info and 'error_type' in cert_info and cert_info['error_type'] == 'PARSE_ERROR':
        warnings.append({
            'level': 'CRITICAL',
            'category': 'CERTIFICATE_PARSE_ERROR',
            'message': cert_info['error'],
            'recommendation': 'Verify certificate format and encoding'
        })
        return warnings
    
    # Check certificate expiry - handle error values gracefully
    not_after_str = cert_info.get('not_valid_after', '')
    not_before_str = cert_info.get('not_valid_before', '')
    
    if not_after_str.startswith('<error:') or not_before_str.startswith('<error:'):
        warnings.append({
            'level': 'MEDIUM',
            'category': 'CERTIFICATE_DATE_ERROR',
            'message': 'Certificate contains invalid or unparseable date fields',
            'recommendation': 'Certificate may be malformed - verify with openssl or other tools'
        })
    else:
        try:
            not_after = datetime.fromisoformat(not_after_str.replace('Z', '+00:00'))
            not_before = datetime.fromisoformat(not_before_str.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            
            if now > not_after:
                warnings.append({
                    'level': 'CRITICAL',
                    'category': 'CERTIFICATE_EXPIRED',
                    'message': f"Certificate expired on {not_after_str}",
                    'recommendation': 'Replace with a valid certificate immediately'
                })
            elif now < not_before:
                warnings.append({
                    'level': 'CRITICAL',
                    'category': 'CERTIFICATE_NOT_YET_VALID',
                    'message': f"Certificate not valid until {not_before_str}",
                    'recommendation': 'Check system time or replace with a valid certificate'
                })
            else:
                days_until_expiry = (not_after - now).days
                if days_until_expiry < CERT_EXPIRY_WARNING_DAYS:
                    warnings.append({
                        'level': 'HIGH',
                        'category': 'CERTIFICATE_EXPIRING_SOON',
                        'message': f"Certificate expires in {days_until_expiry} days",
                        'recommendation': 'Plan certificate renewal to avoid service disruption'
                    })
        except Exception as e:
            warnings.append({
                'level': 'MEDIUM',
                'category': 'CERTIFICATE_DATE_CHECK_ERROR',
                'message': f"Could not verify certificate dates: {str(e)}",
                'recommendation': 'Manually verify certificate validity dates'
            })
    
    # Check self-signed certificates
    if cert_info.get('is_self_signed', False):
        warnings.append({
            'level': 'MEDIUM',
            'category': 'SELF_SIGNED_CERTIFICATE',
            'message': 'Certificate is self-signed',
            'recommendation': 'Use a certificate signed by a trusted Certificate Authority'
        })
    
    # Check key size
    key_type = cert_info.get('key_type', 'Unknown')
    key_size = cert_info.get('key_size', 0)
    
    if key_type == 'RSA' and key_size < MIN_RSA_KEY_SIZE:
        warnings.append({
            'level': 'HIGH',
            'category': 'WEAK_KEY_SIZE',
            'message': f"RSA key size {key_size} bits is below recommended minimum of {MIN_RSA_KEY_SIZE} bits",
            'recommendation': f'Use RSA keys with at least {MIN_RSA_KEY_SIZE} bits'
        })
    elif key_type == 'DSA' and key_size < MIN_DSA_KEY_SIZE:
        warnings.append({
            'level': 'HIGH',
            'category': 'WEAK_KEY_SIZE',
            'message': f"DSA key size {key_size} bits is below recommended minimum of {MIN_DSA_KEY_SIZE} bits",
            'recommendation': f'Use DSA keys with at least {MIN_DSA_KEY_SIZE} bits'
        })
    elif key_type == 'EC' and key_size < MIN_EC_KEY_SIZE:
        warnings.append({
            'level': 'HIGH',
            'category': 'WEAK_KEY_SIZE',
            'message': f"EC key size {key_size} bits is below recommended minimum of {MIN_EC_KEY_SIZE} bits",
            'recommendation': f'Use EC keys with at least {MIN_EC_KEY_SIZE} bits'
        })
    
    # Check signature algorithm
    sig_algo = cert_info.get('signature_algorithm', '').lower()
    if 'md5' in sig_algo:
        warnings.append({
            'level': 'CRITICAL',
            'category': 'WEAK_SIGNATURE_ALGORITHM',
            'message': 'Certificate uses MD5 signature algorithm which is cryptographically broken',
            'recommendation': 'Replace with a certificate using SHA-256 or stronger'
        })
    elif 'sha1' in sig_algo:
        warnings.append({
            'level': 'HIGH',
            'category': 'WEAK_SIGNATURE_ALGORITHM',
            'message': 'Certificate uses SHA-1 signature algorithm which is deprecated',
            'recommendation': 'Replace with a certificate using SHA-256 or stronger'
        })
    
    return warnings


def check_tls_security(connection_info):
    """Check TLS version and cipher suite security"""
    warnings = []
    
    # Check TLS version
    tls_version = connection_info.get('tls_version', '')
    if tls_version in ['TLSv1', 'TLSv1.0']:
        warnings.append({
            'level': 'HIGH',
            'category': 'DEPRECATED_TLS_VERSION',
            'message': 'TLS 1.0 is deprecated and has known vulnerabilities',
            'recommendation': 'Upgrade to TLS 1.2 or TLS 1.3'
        })
    elif tls_version == 'TLSv1.1':
        warnings.append({
            'level': 'HIGH',
            'category': 'DEPRECATED_TLS_VERSION',
            'message': 'TLS 1.1 is deprecated and has known vulnerabilities',
            'recommendation': 'Upgrade to TLS 1.2 or TLS 1.3'
        })
    elif tls_version == 'SSLv3':
        warnings.append({
            'level': 'CRITICAL',
            'category': 'INSECURE_SSL_VERSION',
            'message': 'SSLv3 is obsolete and vulnerable to POODLE attack',
            'recommendation': 'Disable SSLv3 and use TLS 1.2 or higher'
        })
    elif tls_version in ['SSLv2', 'SSLv2.0']:
        warnings.append({
            'level': 'CRITICAL',
            'category': 'INSECURE_SSL_VERSION',
            'message': 'SSLv2 is obsolete and has critical vulnerabilities',
            'recommendation': 'Disable SSLv2 and use TLS 1.2 or higher'
        })
    
    # Check cipher suite
    cipher_suite = connection_info.get('cipher_suite', '')
    if cipher_suite:
        # Check for weak ciphers
        for weak_cipher in WEAK_CIPHERS:
            if weak_cipher in cipher_suite:
                warnings.append({
                    'level': 'HIGH',
                    'category': 'WEAK_CIPHER_SUITE',
                    'message': f"Cipher suite '{cipher_suite}' uses weak encryption ({weak_cipher})",
                    'recommendation': 'Configure server to use strong cipher suites with AES-GCM or ChaCha20-Poly1305'
                })
                break
        
        # Check for PFS
        has_pfs = any(pfs in cipher_suite for pfs in PFS_CIPHERS)
        if not has_pfs and 'TLS_AES' not in cipher_suite:  # TLS 1.3 ciphers have PFS by default
            warnings.append({
                'level': 'MEDIUM',
                'category': 'NO_PERFECT_FORWARD_SECRECY',
                'message': 'Cipher suite does not support Perfect Forward Secrecy (PFS)',
                'recommendation': 'Use cipher suites with ECDHE or DHE key exchange for PFS'
            })
    
    # Check for SSL errors
    if 'ssl_error' in connection_info:
        warnings.append({
            'level': 'HIGH',
            'category': 'SSL_CONNECTION_ERROR',
            'message': f"SSL connection error: {connection_info['ssl_error']}",
            'recommendation': 'Verify SSL/TLS configuration and certificate validity'
        })
    
    return warnings

def _add_vulnerability_indicators(cert_info, warnings):
    """Add vulnerability indicators to certificate fields based on warnings"""
    enhanced_cert_info = cert_info.copy()
    
    # Add vulnerability indicators for each field
    for warning in warnings:
        category = warning.get('category', '')
        
        # Certificate expiry issues
        if category in ['CERTIFICATE_EXPIRED', 'CERTIFICATE_EXPIRING_SOON']:
            enhanced_cert_info['not_valid_after_vulnerable'] = True
            enhanced_cert_info['not_valid_after_vulnerability'] = warning['message']
        elif category == 'CERTIFICATE_NOT_YET_VALID':
            enhanced_cert_info['not_valid_before_vulnerable'] = True
            enhanced_cert_info['not_valid_before_vulnerability'] = warning['message']
        
        # Self-signed certificate
        elif category == 'SELF_SIGNED_CERTIFICATE' and enhanced_cert_info.get('is_self_signed'):
            enhanced_cert_info['is_self_signed_vulnerable'] = True
            enhanced_cert_info['is_self_signed_vulnerability'] = warning['message']
        
        # Weak key size
        elif category == 'WEAK_KEY_SIZE':
            enhanced_cert_info['key_size_vulnerable'] = True
            enhanced_cert_info['key_size_vulnerability'] = warning['message']
        
        # Weak signature algorithm
        elif category == 'WEAK_SIGNATURE_ALGORITHM':
            enhanced_cert_info['signature_algorithm_vulnerable'] = True
            enhanced_cert_info['signature_algorithm_vulnerability'] = warning['message']
    
    return enhanced_cert_info

def checkTLSSecurity(session):
    """Main function to check TLS security in background thread"""
    result = {
        'status': 'error',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'connection': {},
        'certificates': [],
        'certificate_info': [],  # New field for enhanced certificate information
        'warnings': [],
        'summary': {}
    }
    
    try:
        # Extract connection information
        host, port = extract_connection_info(session)
        
        # Get certificates and connection info
        certificates, connection_info = get_certificate_chain(host, port)
        result['connection'] = connection_info
        
        if not connection_info.get('connected', False):
            # Generate specific warnings based on error type
            error_type = connection_info.get('error_type', 'UNKNOWN')
            error_msg = connection_info.get('error', connection_info.get('ssl_error', f'Unknown error connecting to {host}:{port}'))
            
            if error_type == 'CONNECTION_REFUSED':
                result['warnings'].append({
                    'level': 'CRITICAL',
                    'category': 'CONNECTION_REFUSED',
                    'message': error_msg,
                    'recommendation': 'Verify that Cassandra is running on the specified host and port'
                })
            elif error_type == 'CONNECTION_TIMEOUT':
                result['warnings'].append({
                    'level': 'CRITICAL',
                    'category': 'CONNECTION_TIMEOUT',
                    'message': error_msg,
                    'recommendation': 'Check network connectivity, firewall rules, and verify the host is reachable'
                })
            elif error_type == 'DNS_ERROR':
                result['warnings'].append({
                    'level': 'CRITICAL',
                    'category': 'DNS_RESOLUTION_FAILED',
                    'message': error_msg,
                    'recommendation': 'Verify the hostname is correct and DNS is properly configured'
                })
            elif error_type == 'NO_TLS':
                result['warnings'].append({
                    'level': 'CRITICAL',
                    'category': 'TLS_NOT_ENABLED',
                    'message': error_msg,
                    'recommendation': 'The service is not using TLS/SSL. Enable TLS in Cassandra configuration'
                })
            elif error_type == 'SSL_ERROR':
                result['warnings'].append({
                    'level': 'CRITICAL',
                    'category': 'TLS_HANDSHAKE_FAILED',
                    'message': f"TLS/SSL handshake failed: {connection_info.get('ssl_error', error_msg)}",
                    'recommendation': 'Check TLS configuration, certificate validity, and supported protocols'
                })
            else:
                # Generic connection error
                result['warnings'].append({
                    'level': 'CRITICAL',
                    'category': 'CONNECTION_ERROR',
                    'message': error_msg,
                    'recommendation': 'Verify connection parameters and TLS configuration'
                })
        else:
            # Analyze each certificate in the chain
            for i, cert_der in enumerate(certificates):
                cert_info = analyze_certificate(cert_der)
                cert_warnings = check_certificate_security(cert_info, connection_info)
                
                # Add vulnerability indicators to cert_info
                enhanced_cert_info = _add_vulnerability_indicators(cert_info, cert_warnings)
                
                cert_result = {
                    'position': i,
                    'type': 'end-entity' if i == 0 else 'intermediate',
                    'info': cert_info,
                    'warnings': cert_warnings
                }
                result['certificates'].append(cert_result)
                result['warnings'].extend(cert_warnings)
                
                # Add enhanced certificate info to new field
                result['certificate_info'].append({
                    'position': i,
                    'type': 'end-entity' if i == 0 else 'intermediate',
                    'details': enhanced_cert_info
                })
            
            # Check TLS/cipher security
            tls_warnings = check_tls_security(connection_info)
            result['warnings'].extend(tls_warnings)
            
            # Add TLS version vulnerability indicator to connection info
            for warning in tls_warnings:
                if warning['category'] in ['DEPRECATED_TLS_VERSION', 'INSECURE_SSL_VERSION']:
                    result['connection']['tls_version_vulnerable'] = True
                    result['connection']['tls_version_vulnerability'] = warning['message']
                elif warning['category'] in ['WEAK_CIPHER_SUITE', 'NO_PERFECT_FORWARD_SECRECY']:
                    result['connection']['cipher_suite_vulnerable'] = True
                    result['connection']['cipher_suite_vulnerability'] = warning['message']
            
            result['status'] = 'success'
        
        # Generate summary
        warning_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for warning in result['warnings']:
            level = warning.get('level', 'LOW')
            warning_counts[level] = warning_counts.get(level, 0) + 1
        
        result['summary'] = {
            'total_warnings': len(result['warnings']),
            'warning_counts': warning_counts,
            'certificates_analyzed': len(result['certificates']),
            'overall_status': 'CRITICAL' if warning_counts['CRITICAL'] > 0 else 
                            'HIGH' if warning_counts['HIGH'] > 0 else
                            'MEDIUM' if warning_counts['MEDIUM'] > 0 else 'OK'
        }
        
    except Exception as e:
        result['error'] = str(e)
        result['traceback'] = traceback.format_exc()
        result['warnings'].append({
            'level': 'CRITICAL',
            'category': 'ANALYSIS_ERROR',
            'message': f"Failed to analyze TLS security: {str(e)}",
            'recommendation': 'Check error details and contact support if needed'
        })
    
    return result

def checkTLSSecurityBackground(id, session):
    result = checkTLSSecurity(session)
    file_name = path.join(tempfile.gettempdir(), f"{id}.tlscheck")
    with open(file_name, "w") as f:
        json.dump(result, f, indent=2)