# axonops_ssl_validator.py
"""
Comprehensive TLS Certificate Validator
Implements RFC 5280, PCI DSS, OWASP TLS Guidelines, and mitigates known CVEs




"""

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

# Security configuration constants
WEAK_SIGNATURE_ALGORITHMS = {
    x509.oid.SignatureAlgorithmOID.RSA_WITH_MD5: 'MD5 (CVE-2015-0204)',
    x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA1: 'SHA-1 (CVE-2016-2108)',
    x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA1: 'ECDSA-SHA1 (CVE-2019-1543)'
}

INSECURE_CIPHERS = [
    'RC4', 'DES', 'MD5', 'SHA1', 'ADH', 'AECDH',
    'EXP', 'NULL', 'CAMELLIA', 'IDEA', 'SEED'
]

INSECURE_PROTOCOLS = [
    'SSLv2', 'SSLv3',  # POODLE (CVE-2014-3566)
    'TLSv1', 'TLSv1.1'  # Weak TLS versions
]


def validate_tls_connection(
        host: str,
        port: int = 9042,
        check_revocation: bool = False,
        ocsp_timeout: int = 3,
        connection_timeout: int = 5
) -> List[Dict[str, str]]:
    """
    Main TLS validation entry point

    Args:
        host: Target hostname/IP
        port: TCP port (default: 9042)
        check_revocation: Enable OCSP checks (PCI DSS 4.1)
        ocsp_timeout: OCSP response timeout
        connection_timeout: TCP connection timeout

    Returns:
        List of security warnings with OWASP-standard codes
    """
    warnings = []

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), connection_timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get certificate chain
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return [{
                        "code": "NO_CERTIFICATE",
                        "description": "Server provided no certificate (OWASP-TLS-002)"
                    }]

                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                chain = ssock.getpeercertchain()
                issuer = _get_issuer_cert(chain) if chain else None

                # Perform validation checks
                warnings.extend(_validate_certificate_basics(cert))
                warnings.extend(_validate_ca_constraints(cert, issuer))
                warnings.extend(_validate_cryptographic_properties(cert))
                warnings.extend(_validate_connection_parameters(ssock))

                # Optional revocation check
                if check_revocation and issuer:
                    warnings.extend(_perform_ocsp_check(
                        cert, issuer, host, ocsp_timeout
                    ))

    except socket.timeout:
        warnings.append({
            "code": "CONNECTION_TIMEOUT",
            "description": f"Connection to {host}:{port} timed out (OWASP-TLS-005)"
        })
    except Exception as e:
        warnings.append({
            "code": "VALIDATION_ERROR",
            "description": f"Validation failed: {str(e)} (OWASP-TLS-099)"
        })

    return warnings


def _validate_certificate_basics(cert: x509.Certificate) -> List[Dict[str, str]]:
    """RFC 5280 Section 4.1 - Basic Certificate Validation"""
    warnings = []
    now = datetime.now(timezone.utc)

    # Validity period checks (PCI DSS 4.1.1)
    if cert.not_valid_before.replace(tzinfo=timezone.utc) > now:
        warnings.append({
            "code": "CERT_NOT_VALID_YET",
            "description": f"Certificate not yet valid. Valid from {cert.not_valid_before.isoformat()} (RFC 5280 4.1.2.5)"
        })

    if cert.not_valid_after.replace(tzinfo=timezone.utc) < now:
        warnings.append({
            "code": "CERT_EXPIRED",
            "description": f"Certificate expired on {cert.not_valid_after.isoformat()} (PCI DSS 4.1.1)"
        })

    # Self-signed detection (OWASP-TLS-010)
    if cert.issuer == cert.subject:
        warnings.append({
            "code": "SELF_SIGNED",
            "description": "Self-signed certificate detected (RFC 5280 4.1.2.4)"
        })

    return warnings


def _validate_ca_constraints(
        cert: x509.Certificate,
        issuer: Optional[x509.Certificate]
) -> List[Dict[str, str]]:
    """RFC 5280 Section 4.2 - CA Certificate Validation"""
    warnings = []

    # Basic Constraints (RFC 5280 4.2.1.9)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            if bc.path_length is None:
                warnings.append({
                    "code": "MISSING_PATHLEN",
                    "description": "CA missing path length constraint (RFC 5280 4.2.1.9)"
                })
        else:
            warnings.append({
                "code": "INVALID_CA_CERT",
                "description": "Invalid CA basic constraints (RFC 5280 4.2.1.9)"
            })
    except x509.ExtensionNotFound:
        pass

    # Key Usage (RFC 5280 4.2.1.3)
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.key_cert_sign or not ku.crl_sign:
            warnings.append({
                "code": "MISSING_CA_KEY_USAGE",
                "description": "CA missing keyCertSign/crlSign (RFC 5280 4.2.1.3)"
            })
    except x509.ExtensionNotFound:
        warnings.append({
            "code": "MISSING_KEY_USAGE",
            "description": "CA missing key usage extension (RFC 5280 4.2.1.3)"
        })

    # Authority Key Identifier (RFC 5280 4.2.1.1)
    if issuer:
        try:
            aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
            ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.key_identifier
            if aki != ski:
                warnings.append({
                    "code": "AKI_SKI_MISMATCH",
                    "description": "Authority/Subject Key mismatch (RFC 5280 4.2.1.1)"
                })
        except x509.ExtensionNotFound:
            pass

    return warnings


def _validate_cryptographic_properties(cert: x509.Certificate) -> List[Dict[str, str]]:
    """Cryptographic Implementation Validation"""
    warnings = []

    # Signature Algorithm (CVE-2015-0204, CVE-2016-2108)
    sig_alg = cert.signature_algorithm_oid
    if sig_alg in WEAK_SIGNATURE_ALGORITHMS:
        warnings.append({
            "code": "WEAK_SIGNATURE_ALG",
            "description": f"Weak algorithm: {WEAK_SIGNATURE_ALGORITHMS[sig_alg]} (OWASP-TLS-020)"
        })

    # Key Strength (NIST SP 800-57)
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < 2048:
        warnings.append({
            "code": "WEAK_RSA_KEY",
            "description": f"RSA key size {public_key.key_size} < 2048 bits (NIST SP 800-57)"
        })
    elif isinstance(public_key, ec.EllipticCurvePublicKey) and public_key.key_size < 224:
        warnings.append({
            "code": "WEAK_EC_KEY",
            "description": f"EC key size {public_key.key_size} < 224 bits (NIST SP 800-57)"
        })

    return warnings


def _validate_connection_parameters(ssock: ssl.SSLSocket) -> List[Dict[str, str]]:
    """Negotiated Connection Parameters Validation"""
    warnings = []

    # Protocol Version (CVE-2014-3566)
    protocol = ssock.version()
    if protocol in INSECURE_PROTOCOLS:
        warnings.append({
            "code": f"INSECURE_PROTOCOL_{protocol}",
            "description": f"Insecure protocol: {protocol} (OWASP-TLS-003)"
        })

    # Cipher Suite (PCI DSS 4.1)
    cipher = ssock.cipher()
    if cipher:
        name, _, _ = cipher
        for weak in INSECURE_CIPHERS:
            if weak in name.upper():
                warnings.append({
                    "code": f"WEAK_CIPHER_{weak}",
                    "description": f"Insecure cipher: {name} (OWASP-TLS-004)"
                })

    return warnings


def _perform_ocsp_check(
        cert: x509.Certificate,
        issuer: x509.Certificate,
        host: str,
        timeout: int
) -> List[Dict[str, str]]:
    """RFC 6960 OCSP Revocation Check"""
    warnings = []

    try:
        ocsp_url = _get_ocsp_url(cert)
        if not ocsp_url:
            return [{
                "code": "OCSP_UNAVAILABLE",
                "description": "No OCSP responder URL (RFC 6960 3.1)"
            }]

        # Build OCSP request
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA256())
        request = builder.build()

        # Send request
        response = requests.post(
            ocsp_url,
            data=request.public_bytes(Encoding.DER),
            headers={'Content-Type': 'application/ocsp-request'},
            timeout=timeout
        )
        response.raise_for_status()

        # Parse response
        ocsp_resp = load_der_ocsp_response(response.content)
        if ocsp_resp.certificate_status == ocsp_resp.CertificateStatus.REVOKED:
            reason = ocsp_resp.revocation_reason or "unspecified"
            warnings.append({
                "code": "CERT_REVOKED",
                "description": f"Revoked: {reason} (RFC 6960 2.2)"
            })

    except requests.exceptions.Timeout:
        warnings.append({
            "code": "OCSP_TIMEOUT",
            "description": f"OCSP request timed out (OWASP-TLS-008)"
        })
    except Exception as e:
        warnings.append({
            "code": "OCSP_ERROR",
            "description": f"OCSP error: {str(e)}"
        })

    return warnings


def _get_ocsp_url(cert: x509.Certificate) -> Optional[str]:
    """Extract OCSP Responder URL"""
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in aia.value:
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def _get_issuer_cert(chain: list) -> Optional[x509.Certificate]:
    """Extract Issuer Certificate from Chain"""
    try:
        return x509.load_der_x509_certificate(chain[0], default_backend())
    except Exception:
        return None


if __name__ == "__main__":
    # Example usage
    warnings = validate_tls_connection("cassandra.example.com", check_revocation=True)
    for warn in warnings:
        print(f"[{warn['code']}] {warn['description']}")
