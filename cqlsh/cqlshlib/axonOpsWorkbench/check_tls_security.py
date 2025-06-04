# Custom module to check TLS/SSL security configuration and certificates
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
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Get all certificates in the chain
    certificates = []
    connection_info = {
        'host': host,
        'port': port,
        'connected': False
    }
    
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get connection info
                connection_info['connected'] = True
                connection_info['tls_version'] = ssock.version()
                connection_info['cipher_suite'] = ssock.cipher()[0] if ssock.cipher() else None
                connection_info['cipher_bits'] = ssock.cipher()[2] if ssock.cipher() and len(ssock.cipher()) > 2 else None
                
                # Get peer certificate (end entity)
                der_cert = ssock.getpeercert_bin()
                if der_cert:
                    certificates.append(der_cert)
                
                # Note: Python's ssl module doesn't provide easy access to the full chain
                # We only get the peer certificate, not intermediates
                # This is a limitation but sufficient for most security checks
                
    except ssl.SSLError as e:
        connection_info['ssl_error'] = str(e)
    except socket.timeout:
        connection_info['error'] = "Connection timeout"
    except Exception as e:
        connection_info['error'] = str(e)
    
    return certificates, connection_info


def analyze_certificate(cert_der):
    """Analyze a certificate for security issues"""
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        cert_info = {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'version': cert.version.name,
            'serial_number': str(cert.serial_number),
            'not_valid_before': cert.not_valid_before_utc.isoformat(),
            'not_valid_after': cert.not_valid_after_utc.isoformat(),
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'is_self_signed': cert.issuer == cert.subject
        }
        
        # Extract key information
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            cert_info['key_type'] = 'RSA'
            cert_info['key_size'] = public_key.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            cert_info['key_type'] = 'DSA'
            cert_info['key_size'] = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            cert_info['key_type'] = 'EC'
            cert_info['key_size'] = public_key.curve.key_size
        else:
            cert_info['key_type'] = 'Unknown'
            cert_info['key_size'] = None
        
        # Extract SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = []
            for san in san_ext.value:
                if isinstance(san, x509.DNSName):
                    sans.append(f"DNS:{san.value}")
                elif isinstance(san, x509.IPAddress):
                    sans.append(f"IP:{san.value}")
            cert_info['subject_alternative_names'] = sans
        except x509.ExtensionNotFound:
            cert_info['subject_alternative_names'] = []
        
        return cert_info
        
    except Exception as e:
        return {'error': f"Failed to parse certificate: {str(e)}"}


def check_certificate_security(cert_info, connection_info):
    """Check certificate for security issues and generate warnings"""
    warnings = []
    
    # Check if certificate could be parsed
    if 'error' in cert_info:
        warnings.append({
            'level': 'CRITICAL',
            'category': 'CERTIFICATE_PARSE_ERROR',
            'message': cert_info['error'],
            'recommendation': 'Verify certificate format and encoding'
        })
        return warnings
    
    # Check certificate expiry
    try:
        not_after = datetime.fromisoformat(cert_info['not_valid_after'].replace('Z', '+00:00'))
        not_before = datetime.fromisoformat(cert_info['not_valid_before'].replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        
        if now > not_after:
            warnings.append({
                'level': 'CRITICAL',
                'category': 'CERTIFICATE_EXPIRED',
                'message': f"Certificate expired on {cert_info['not_valid_after']}",
                'recommendation': 'Replace with a valid certificate immediately'
            })
        elif now < not_before:
            warnings.append({
                'level': 'CRITICAL',
                'category': 'CERTIFICATE_NOT_YET_VALID',
                'message': f"Certificate not valid until {cert_info['not_valid_before']}",
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


def checkTLSSecurityBackground(id, session):
    """Main function to check TLS security in background thread"""
    result = {
        'status': 'error',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'connection': {},
        'certificates': [],
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
            result['warnings'].append({
                'level': 'CRITICAL',
                'category': 'CONNECTION_FAILED',
                'message': f"Failed to establish TLS connection: {connection_info.get('error', 'Unknown error')}",
                'recommendation': 'Verify network connectivity and TLS configuration'
            })
        else:
            # Analyze each certificate in the chain
            for i, cert_der in enumerate(certificates):
                cert_info = analyze_certificate(cert_der)
                cert_warnings = check_certificate_security(cert_info, connection_info)
                
                cert_result = {
                    'position': i,
                    'type': 'end-entity' if i == 0 else 'intermediate',
                    'info': cert_info,
                    'warnings': cert_warnings
                }
                result['certificates'].append(cert_result)
                result['warnings'].extend(cert_warnings)
            
            # Check TLS/cipher security
            tls_warnings = check_tls_security(connection_info)
            result['warnings'].extend(tls_warnings)
            
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
    
    # Write results to file
    file_name = path.join(tempfile.gettempdir(), f"{id}.tlscheck")
    with open(file_name, "w") as f:
        json.dump(result, f, indent=2)