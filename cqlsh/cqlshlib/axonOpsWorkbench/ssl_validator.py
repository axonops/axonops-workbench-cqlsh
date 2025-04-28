# axonOpsWorkbench/ssl_validator.py
"""
Comprehensive TLS Certificate Validation for Cassandra Connections

Usage Example:

from cassandra.cluster import Cluster
from axonOpsWorkbench.ssl_validator import validate_cassandra_ssl

# Create cluster connection with SSL
cluster = Cluster(
    contact_points=['cassandra-host'],
    ssl_options={
        'ca_certs': '/path/to/ca.crt',
        'ssl_version': ssl.PROTOCOL_TLSv1_2
    }
)

# Basic check
if cluster.ssl_options or cluster.ssl_context:
    warnings = validate_cassandra_ssl(cluster)
    for warning in warnings:
        print(f"[{warning['code']}] {warning['description']}")
else:
    print("SSL not enabled - skipping certificate checks")


# With OCSP revocation check
if cluster.ssl_options or cluster.ssl_context:
    warnings = validate_cassandra_ssl(cluster, check_revocation=True, ocsp_timeout=5)
    for warning in warnings:
        print(f"[{warning['code']}] {warning['description']}")
else:
    print("SSL not enabled - skipping certificate checks")


"""

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding


def validate_cassandra_ssl(
        cluster: Any,
        check_revocation: bool = False,
        ocsp_timeout: int = 3
) -> List[Dict[str, str]]:
    """
    Main validation entry point with optional OCSP revocation checks

    Args:
        cluster: Cassandra Cluster/Session object
        check_revocation: Enable OCSP revocation checks (default: False)
        ocsp_timeout: OCSP request timeout in seconds (default: 3)
    """
    warnings = []

    try:
        from cassandra.cluster import Cluster, Session

        # Validate input type
        if isinstance(cluster, Cluster):
            session = cluster.session if hasattr(cluster, 'session') else None
            cluster_obj = cluster
        elif isinstance(cluster, Session):
            session = cluster
            cluster_obj = session.cluster
        else:
            return [{"code": "INVALID_INPUT", "description": "Requires Cluster/Session object"}]

        # Check SSL activation
        if not _is_ssl_activated(cluster_obj):
            return [{"code": "SSL_NOT_ENABLED", "description": "SSL not configured"}]

        # Get connection parameters
        host, port = _get_connection_params(cluster_obj)
        if not host:
            return [{"code": "NO_CONTACT_POINTS", "description": "No cluster contact points"}]

        # Perform full certificate validation
        return _validate_certificate_chain(
            host,
            port,
            check_revocation=check_revocation,
            ocsp_timeout=ocsp_timeout
        )

    except Exception as e:
        return [{"code": "VALIDATION_ERROR", "description": f"Validation failed: {str(e)}"}]


def _validate_certificate_chain(
        host: str,
        port: int,
        check_revocation: bool,
        ocsp_timeout: int,
        connection_timeout: int = 5
) -> List[Dict[str, str]]:
    """Perform comprehensive certificate validation with OCSP optional checks"""
    warnings = []

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=connection_timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get certificate chain
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return [{"code": "NO_CERTIFICATE", "description": "No server certificate"}]

                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                chain = ssock.getpeercertchain()
                issuer = _get_issuer_cert(chain) if chain else None

                # Core certificate validation
                warnings.extend(_validate_certificate_basics(cert))
                warnings.extend(_validate_certificate_cryptography(cert))
                warnings.extend(_validate_connection_ciphers(ssock))

                # Optional OCSP revocation check
                if check_revocation and issuer:
                    warnings.extend(_perform_ocsp_check(
                        cert,
                        issuer,
                        host,
                        ocsp_timeout
                    ))

    except socket.timeout:
        warnings.append({"code": "CONNECTION_TIMEOUT", "description": f"Connection to {host}:{port} timed out"})
    except Exception as e:
        warnings.append({"code": "CHECK_ERROR", "description": f"Validation error: {str(e)}"})

    return warnings


def _validate_certificate_basics(cert: x509.Certificate) -> List[Dict[str, str]]:
    """Validate fundamental certificate properties"""
    warnings = []
    now = datetime.now(timezone.utc)

    # Validity period checks
    if cert.not_valid_before.replace(tzinfo=timezone.utc) > now:
        warnings.append({
            "code": "CERT_NOT_VALID_YET",
            "description": f"Valid from {cert.not_valid_before.isoformat()}"
        })

    if cert.not_valid_after.replace(tzinfo=timezone.utc) < now:
        warnings.append({
            "code": "CERT_EXPIRED",
            "description": f"Expired on {cert.not_valid_after.isoformat()}"
        })

    # Self-signed check
    if cert.issuer == cert.subject:
        warnings.append({
            "code": "SELF_SIGNED",
            "description": "Self-signed certificate detected"
        })

    return warnings


def _validate_certificate_cryptography(cert: x509.Certificate) -> List[Dict[str, str]]:
    """Validate cryptographic properties of certificate"""
    warnings = []
    public_key = cert.public_key()

    # Key strength checks
    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < 2048:
        warnings.append({
            "code": "WEAK_RSA_KEY",
            "description": f"RSA key size {public_key.key_size} < 2048 bits"
        })
    elif isinstance(public_key, dsa.DSAPublicKey) and public_key.key_size < 2048:
        warnings.append({
            "code": "WEAK_DSA_KEY",
            "description": f"DSA key size {public_key.key_size} < 2048 bits"
        })
    elif isinstance(public_key, ec.EllipticCurvePublicKey) and public_key.key_size < 224:
        warnings.append({
            "code": "WEAK_EC_KEY",
            "description": f"EC key size {public_key.key_size} < 224 bits"
        })

    # Signature algorithm checks
    sig_alg = cert.signature_algorithm_oid
    weak_algs = {
        x509.oid.SignatureAlgorithmOID.RSA_WITH_MD5: "MD5",
        x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA1: "SHA1"
    }
    if sig_alg in weak_algs:
        warnings.append({
            "code": "WEAK_SIGNATURE_ALG",
            "description": f"Weak signature algorithm: {weak_algs[sig_alg]}"
        })

    return warnings


def _validate_connection_ciphers(ssock: ssl.SSLSocket) -> List[Dict[str, str]]:
    """Validate negotiated cipher parameters"""
    warnings = []
    cipher = ssock.cipher()

    if cipher:
        name, version, bits = cipher

        # Protocol version checks
        insecure_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        if version in insecure_protocols:
            warnings.append({
                "code": f"INSECURE_PROTOCOL_{version.replace('.', '_')}",
                "description": f"Insecure protocol: {version}"
            })

        # Cipher suite checks
        weak_ciphers = ['RC4', 'DES', 'NULL', 'EXP', 'MD5', 'SHA1', 'ADH', 'AECDH']
        for pattern in weak_ciphers:
            if pattern in name.upper():
                warnings.append({
                    "code": f"WEAK_CIPHER_{pattern}",
                    "description": f"Insecure cipher: {name}"
                })

    return warnings


def _perform_ocsp_check(
        cert: x509.Certificate,
        issuer: x509.Certificate,
        host: str,
        timeout: int
) -> List[Dict[str, str]]:
    """Perform OCSP revocation check with proper timeout handling"""
    warnings = []

    try:
        ocsp_url = _get_ocsp_url(cert)
        if not ocsp_url:
            return [{
                "code": "OCSP_UNAVAILABLE",
                "description": "No OCSP responder URL in certificate"
            }]

        # Build OCSP request
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA1())
        request = builder.build()

        # Send request with timeout
        response = requests.post(
            ocsp_url,
            data=request.public_bytes(Encoding.DER),
            headers={'Content-Type': 'application/ocsp-request'},
            timeout=(timeout, timeout)
        )
        response.raise_for_status()

        # Parse response
        ocsp_resp = load_der_ocsp_response(response.content)
        status = ocsp_resp.certificate_status

        if status == ocsp_resp.CertificateStatus.REVOKED:
            reason = ocsp_resp.revocation_reason or "unspecified"
            warnings.append({
                "code": "CERT_REVOKED",
                "description": f"Certificate revoked: {reason}"
            })

    except requests.exceptions.Timeout:
        warnings.append({
            "code": "OCSP_TIMEOUT",
            "description": f"OCSP request to {ocsp_url} timed out"
        })
    except requests.exceptions.RequestException as e:
        warnings.append({
            "code": "OCSP_ERROR",
            "description": f"OCSP check failed: {str(e)}"
        })
    except Exception as e:
        warnings.append({
            "code": "OCSP_ERROR",
            "description": f"OCSP processing error: {str(e)}"
        })

    return warnings


def _get_ocsp_url(cert: x509.Certificate) -> Optional[str]:
    """Extract OCSP responder URL from certificate"""
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for desc in aia.value:
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def _get_issuer_cert(chain: list) -> Optional[x509.Certificate]:
    """Extract issuer certificate from chain"""
    try:
        return x509.load_der_x509_certificate(chain[0], default_backend())
    except Exception:
        return None


def _is_ssl_activated(cluster: Any) -> bool:
    """Check if SSL is enabled on the cluster"""
    return any([
        getattr(cluster, 'ssl_context', None),
        getattr(cluster, 'ssl_options', None),
        getattr(cluster, 'ssl', None)
    ])


def _get_connection_params(cluster: Any) -> tuple:
    """Extract primary contact point and port"""
    if not getattr(cluster, 'contact_points', None):
        return (None, None)
    return (
        cluster.contact_points[0],
        getattr(cluster, 'port', 9042)
    )
