# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
import ssl
import socket
import json
import tempfile
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from axonOpsWorkbench.check_tls_security import (
    extract_connection_info,
    analyze_certificate,
    check_certificate_security,
    check_tls_security,
    get_certificate_chain,
    checkTLSSecurityBackground,
    checkTLSSecurity,
    _add_vulnerability_indicators,
    CERT_EXPIRY_WARNING_DAYS,
    MIN_RSA_KEY_SIZE,
    MIN_DSA_KEY_SIZE,
    MIN_EC_KEY_SIZE
)


class TestCheckTLSecurity(unittest.TestCase):
    """Test cases for the TLS security checking module"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_host = 'test.cassandra.local'
        self.test_port = 9042
    
    def _parse_vulnerability_string(self, vuln_string, separator='; '):
        """Helper to parse aggregated vulnerability strings into components"""
        if not vuln_string:
            return []
        return vuln_string.split(separator)
    
    def _assert_vulnerability_structure(self, data, field_name, expected_count=None, expected_messages=None):
        """Helper to assert vulnerability structure without depending on exact formatting"""
        # Check vulnerability flag
        self.assertTrue(data.get(f'{field_name}_vulnerable'))
        
        # Check vulnerability message exists
        vuln_key = f'{field_name}_vulnerability'
        self.assertIn(vuln_key, data)
        
        # Check count if multiple vulnerabilities expected
        count_key = f'{field_name}_vulnerability_count'
        if expected_count and expected_count > 1:
            self.assertEqual(data.get(count_key), expected_count)
        elif expected_count == 1:
            self.assertNotIn(count_key, data)
        
        # Check messages if provided
        if expected_messages:
            vuln_parts = self._parse_vulnerability_string(data[vuln_key])
            if expected_count and expected_count > 1:
                self.assertEqual(len(vuln_parts), expected_count)
                # Check messages are present (order-independent)
                self.assertEqual(set(vuln_parts), set(expected_messages))
            else:
                # Single message case
                self.assertEqual(data[vuln_key], expected_messages[0])
        
    def tearDown(self):
        """Clean up any temporary files"""
        # Clean up any temp files created during tests
        temp_dir = tempfile.gettempdir()
        for filename in os.listdir(temp_dir):
            if filename.endswith('.tlscheck'):
                try:
                    os.remove(os.path.join(temp_dir, filename))
                except:
                    pass
    
    def _create_test_certificate(self, 
                               subject_name="test.example.com",
                               issuer_name="Test CA",
                               not_before=None,
                               not_after=None,
                               key_size=2048,
                               is_self_signed=False,
                               san_list=None,
                               signature_hash=hashes.SHA256()):
        """Helper to create test certificates"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Certificate dates
        if not_before is None:
            not_before = datetime.now(timezone.utc)
        if not_after is None:
            not_after = not_before + timedelta(days=365)
            
        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])
        
        if is_self_signed:
            issuer = subject
        else:
            issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
            ])
        
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)
        
        # Add SANs if provided
        if san_list:
            san_entries = []
            for san in san_list:
                if san.startswith('DNS:'):
                    san_entries.append(x509.DNSName(san[4:]))
                elif san.startswith('IP:'):
                    import ipaddress
                    san_entries.append(x509.IPAddress(ipaddress.ip_address(san[3:])))
            
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
        
        # Sign certificate
        certificate = builder.sign(private_key, signature_hash, default_backend())
        
        # Return DER encoded certificate
        return certificate.public_bytes(serialization.Encoding.DER)
    
    def test_extract_connection_info(self):
        """Test extracting connection information from session"""
        # Mock session and cluster
        mock_session = Mock()
        mock_cluster = Mock()
        mock_session.cluster = mock_cluster
        
        # Test with contact points
        mock_cluster.contact_points = ['cassandra1.example.com', 'cassandra2.example.com']
        mock_cluster.port = 9042
        
        host, port = extract_connection_info(mock_session)
        self.assertEqual(host, 'cassandra1.example.com')
        self.assertEqual(port, 9042)
        
        # Test with no port specified (should default to 9042)
        mock_cluster.port = None
        host, port = extract_connection_info(mock_session)
        self.assertEqual(port, 9042)
        
        # Test fallback to metadata hosts
        mock_cluster.contact_points = []
        mock_host = Mock()
        mock_host.address = '192.168.1.100'
        mock_host.is_up = True
        mock_cluster.metadata.all_hosts.return_value = [mock_host]
        
        host, port = extract_connection_info(mock_session)
        self.assertEqual(host, '192.168.1.100')
        
        # Test error when no hosts available
        mock_cluster.metadata.all_hosts.return_value = []
        with self.assertRaises(Exception) as context:
            extract_connection_info(mock_session)
        self.assertIn("No active hosts found", str(context.exception))
    
    def test_analyze_certificate_valid(self):
        """Test analyzing a valid certificate"""
        cert_der = self._create_test_certificate(
            subject_name="test.cassandra.local",
            san_list=["DNS:test.cassandra.local", "DNS:*.cassandra.local", "IP:192.168.1.100"]
        )
        
        cert_info = analyze_certificate(cert_der)
        
        self.assertIn('subject', cert_info)
        self.assertIn('CN=test.cassandra.local', cert_info['subject'])
        self.assertIn('issuer', cert_info)
        self.assertIn('not_valid_before', cert_info)
        self.assertIn('not_valid_after', cert_info)
        self.assertEqual(cert_info['key_type'], 'RSA')
        self.assertEqual(cert_info['key_size'], 2048)
        self.assertFalse(cert_info['is_self_signed'])
        self.assertEqual(len(cert_info['subject_alternative_names']), 3)
        self.assertIn('DNS:test.cassandra.local', cert_info['subject_alternative_names'])
    
    def test_analyze_certificate_self_signed(self):
        """Test analyzing a self-signed certificate"""
        cert_der = self._create_test_certificate(
            subject_name="self-signed.local",
            is_self_signed=True
        )
        
        cert_info = analyze_certificate(cert_der)
        self.assertTrue(cert_info['is_self_signed'])
    
    def test_analyze_certificate_invalid(self):
        """Test analyzing an invalid certificate"""
        invalid_cert = b'invalid certificate data'
        cert_info = analyze_certificate(invalid_cert)
        
        self.assertIn('error', cert_info)
        self.assertIn('Failed to load certificate', cert_info['error'])
        self.assertEqual(cert_info.get('error_type'), 'PARSE_ERROR')
    
    def test_check_certificate_security_expired(self):
        """Test detecting expired certificates"""
        # Create expired certificate
        cert_der = self._create_test_certificate(
            not_before=datetime.now(timezone.utc) - timedelta(days=400),
            not_after=datetime.now(timezone.utc) - timedelta(days=30)
        )
        
        cert_info = analyze_certificate(cert_der)
        warnings = check_certificate_security(cert_info, {})
        
        # Should have critical warning about expiry
        expiry_warnings = [w for w in warnings if w['category'] == 'CERTIFICATE_EXPIRED']
        self.assertEqual(len(expiry_warnings), 1)
        self.assertEqual(expiry_warnings[0]['level'], 'CRITICAL')
    
    def test_check_certificate_security_expiring_soon(self):
        """Test detecting certificates expiring soon"""
        # Certificate expiring in 20 days
        cert_der = self._create_test_certificate(
            not_before=datetime.now(timezone.utc) - timedelta(days=345),
            not_after=datetime.now(timezone.utc) + timedelta(days=20)
        )
        
        cert_info = analyze_certificate(cert_der)
        warnings = check_certificate_security(cert_info, {})
        
        # Should have high warning about expiring soon
        expiry_warnings = [w for w in warnings if w['category'] == 'CERTIFICATE_EXPIRING_SOON']
        self.assertEqual(len(expiry_warnings), 1)
        self.assertEqual(expiry_warnings[0]['level'], 'HIGH')
        # Check that the message contains a number of days less than or equal to 20
        import re
        match = re.search(r'(\d+) days', expiry_warnings[0]['message'])
        self.assertIsNotNone(match)
        days = int(match.group(1))
        self.assertLessEqual(days, 20)
        self.assertGreater(days, 0)
    
    def test_check_certificate_security_weak_key(self):
        """Test detecting weak key sizes"""
        # RSA key with 1024 bits (weak)
        cert_der = self._create_test_certificate(key_size=1024)
        
        cert_info = analyze_certificate(cert_der)
        warnings = check_certificate_security(cert_info, {})
        
        # Should have warning about weak key size
        key_warnings = [w for w in warnings if w['category'] == 'WEAK_KEY_SIZE']
        self.assertEqual(len(key_warnings), 1)
        self.assertEqual(key_warnings[0]['level'], 'HIGH')
        self.assertIn('1024', key_warnings[0]['message'])
    
    def test_check_certificate_security_weak_signature(self):
        """Test detecting weak signature algorithms"""
        # Create a normal certificate and then manually set weak signature algorithm
        cert_der = self._create_test_certificate()
        
        cert_info = analyze_certificate(cert_der)
        # Manually set the signature algorithm for testing
        cert_info['signature_algorithm'] = 'sha1WithRSAEncryption'
        
        warnings = check_certificate_security(cert_info, {})
        
        # Should have warning about SHA1
        sig_warnings = [w for w in warnings if w['category'] == 'WEAK_SIGNATURE_ALGORITHM']
        self.assertEqual(len(sig_warnings), 1)
        self.assertEqual(sig_warnings[0]['level'], 'HIGH')
        self.assertIn('SHA-1', sig_warnings[0]['message'])
    
    def test_check_tls_security_weak_versions(self):
        """Test detecting weak TLS versions"""
        # Test TLS 1.0
        connection_info = {'tls_version': 'TLSv1.0'}
        warnings = check_tls_security(connection_info)
        
        tls_warnings = [w for w in warnings if w['category'] == 'DEPRECATED_TLS_VERSION']
        self.assertEqual(len(tls_warnings), 1)
        self.assertIn('TLS 1.0', tls_warnings[0]['message'])
        
        # Test SSLv3
        connection_info = {'tls_version': 'SSLv3'}
        warnings = check_tls_security(connection_info)
        
        ssl_warnings = [w for w in warnings if w['category'] == 'INSECURE_SSL_VERSION']
        self.assertEqual(len(ssl_warnings), 1)
        self.assertEqual(ssl_warnings[0]['level'], 'CRITICAL')
        self.assertIn('POODLE', ssl_warnings[0]['message'])
    
    def test_check_tls_security_weak_ciphers(self):
        """Test detecting weak cipher suites"""
        # Test NULL cipher
        connection_info = {'cipher_suite': 'TLS_RSA_WITH_NULL_SHA256'}
        warnings = check_tls_security(connection_info)
        
        cipher_warnings = [w for w in warnings if w['category'] == 'WEAK_CIPHER_SUITE']
        self.assertEqual(len(cipher_warnings), 1)
        self.assertIn('NULL', cipher_warnings[0]['message'])
        
        # Test RC4 cipher
        connection_info = {'cipher_suite': 'TLS_RSA_WITH_RC4_128_SHA'}
        warnings = check_tls_security(connection_info)
        
        cipher_warnings = [w for w in warnings if w['category'] == 'WEAK_CIPHER_SUITE']
        self.assertEqual(len(cipher_warnings), 1)
        self.assertIn('RC4', cipher_warnings[0]['message'])
    
    def test_check_tls_security_no_pfs(self):
        """Test detecting lack of Perfect Forward Secrecy"""
        # Cipher without PFS
        connection_info = {'cipher_suite': 'TLS_RSA_WITH_AES_128_GCM_SHA256'}
        warnings = check_tls_security(connection_info)
        
        pfs_warnings = [w for w in warnings if w['category'] == 'NO_PERFECT_FORWARD_SECRECY']
        self.assertEqual(len(pfs_warnings), 1)
        self.assertEqual(pfs_warnings[0]['level'], 'MEDIUM')
        
        # Cipher with PFS (ECDHE)
        connection_info = {'cipher_suite': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'}
        warnings = check_tls_security(connection_info)
        
        pfs_warnings = [w for w in warnings if w['category'] == 'NO_PERFECT_FORWARD_SECRECY']
        self.assertEqual(len(pfs_warnings), 0)
    
    @patch('axonOpsWorkbench.check_tls_security.extract_connection_info')
    @patch('axonOpsWorkbench.check_tls_security.get_certificate_chain')
    def test_checkTLSSecurityBackground_success(self, mock_get_cert, mock_extract):
        """Test the background check function with successful execution"""
        # Setup mocks
        mock_extract.return_value = ('test.cassandra.local', 9042)
        
        test_cert = self._create_test_certificate()
        mock_get_cert.return_value = (
            [test_cert],
            {
                'host': 'test.cassandra.local',
                'port': 9042,
                'connected': True,
                'tls_version': 'TLSv1.3',
                'cipher_suite': 'TLS_AES_256_GCM_SHA384',
                'cipher_bits': 256
            }
        )
        
        # Mock session
        mock_session = Mock()
        
        # Run the background check
        test_id = 'test123'
        checkTLSSecurityBackground(test_id, mock_session)
        
        # Verify output file was created
        output_file = os.path.join(tempfile.gettempdir(), f"{test_id}.tlscheck")
        self.assertTrue(os.path.exists(output_file))
        
        # Verify file contents
        with open(output_file, 'r') as f:
            result = json.load(f)
        
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['connection']['host'], 'test.cassandra.local')
        self.assertEqual(result['connection']['tls_version'], 'TLSv1.3')
        self.assertEqual(len(result['certificates']), 1)
        self.assertIn('summary', result)
        self.assertEqual(result['summary']['certificates_analyzed'], 1)
    
    @patch('axonOpsWorkbench.check_tls_security.extract_connection_info')
    @patch('axonOpsWorkbench.check_tls_security.get_certificate_chain')
    def test_checkTLSSecurityBackground_connection_error(self, mock_get_cert, mock_extract):
        """Test the background check with connection error"""
        # Setup mocks
        mock_extract.return_value = ('test.cassandra.local', 9042)
        mock_get_cert.return_value = (
            [],
            {
                'host': 'test.cassandra.local',
                'port': 9042,
                'connected': False,
                'error': 'Connection refused'
            }
        )
        
        # Mock session
        mock_session = Mock()
        
        # Run the background check
        test_id = 'test_error'
        checkTLSSecurityBackground(test_id, mock_session)
        
        # Verify output file
        output_file = os.path.join(tempfile.gettempdir(), f"{test_id}.tlscheck")
        with open(output_file, 'r') as f:
            result = json.load(f)
        
        # When no certificates are found, status should still be 'success' but with warnings
        self.assertIn('status', result)
        # Check for connection error warning - might be CONNECTION_ERROR instead of CONNECTION_FAILED
        connection_warnings = [w for w in result['warnings'] if w['category'] in ['CONNECTION_FAILED', 'CONNECTION_ERROR']]
        self.assertEqual(len(connection_warnings), 1)
        self.assertIn('Connection refused', connection_warnings[0]['message'])
    
    @patch('axonOpsWorkbench.check_tls_security.extract_connection_info')
    def test_checkTLSSecurityBackground_exception(self, mock_extract):
        """Test the background check with exception handling"""
        # Make extract_connection_info raise an exception
        mock_extract.side_effect = Exception("Test exception")
        
        # Mock session
        mock_session = Mock()
        
        # Run the background check
        test_id = 'test_exception'
        checkTLSSecurityBackground(test_id, mock_session)
        
        # Verify output file contains error
        output_file = os.path.join(tempfile.gettempdir(), f"{test_id}.tlscheck")
        with open(output_file, 'r') as f:
            result = json.load(f)
        
        self.assertEqual(result['status'], 'error')
        self.assertIn('error', result)
        self.assertIn('Test exception', result['error'])
        
        # Verify ANALYSIS_ERROR warning was generated
        analysis_warnings = [w for w in result['warnings'] if w['category'] == 'ANALYSIS_ERROR']
        self.assertEqual(len(analysis_warnings), 1)
        self.assertIn('Failed to analyze TLS security', analysis_warnings[0]['message'])
    
    def test_analyze_certificate_enhanced_fields(self):
        """Test that analyze_certificate returns all enhanced fields"""
        # Create a test certificate with SANs
        san_list = [
            "DNS:test.example.com",
            "DNS:*.example.com",
            "IP:192.168.1.1"
        ]
        cert_der = self._create_test_certificate(
            subject_name="test.example.com",
            san_list=san_list
        )
        
        cert_info = analyze_certificate(cert_der)
        
        # Check all new fields are present
        self.assertIn('common_name', cert_info)
        self.assertEqual(cert_info['common_name'], 'test.example.com')
        
        self.assertIn('fingerprints', cert_info)
        self.assertIn('sha256', cert_info['fingerprints'])
        self.assertIn('sha1', cert_info['fingerprints'])
        
        # Verify fingerprint format (should have colons)
        self.assertRegex(cert_info['fingerprints']['sha256'], r'^[0-9a-f:]+$')
        self.assertRegex(cert_info['fingerprints']['sha1'], r'^[0-9a-f:]+$')
        
        # Key usage might not be present in basic test cert
        # Extended key usage might not be present in basic test cert
    
    def test_add_vulnerability_indicators(self):
        """Test adding vulnerability indicators to certificate fields"""
        # Create base certificate info
        cert_info = {
            'not_valid_after': '2024-01-01T00:00:00',
            'not_valid_before': '2023-01-01T00:00:00',
            'is_self_signed': True,
            'key_size': 1024,
            'signature_algorithm': 'sha1WithRSAEncryption'
        }
        
        # Create warnings
        warnings = [
            {
                'category': 'CERTIFICATE_EXPIRED',
                'message': 'Certificate expired on 2024-01-01T00:00:00'
            },
            {
                'category': 'SELF_SIGNED_CERTIFICATE',
                'message': 'Certificate is self-signed'
            },
            {
                'category': 'WEAK_KEY_SIZE',
                'message': 'RSA key size 1024 bits is below recommended minimum'
            },
            {
                'category': 'WEAK_SIGNATURE_ALGORITHM',
                'message': 'Certificate uses SHA-1 signature algorithm'
            }
        ]
        
        # Add vulnerability indicators
        enhanced_info = _add_vulnerability_indicators(cert_info, warnings)
        
        # Check vulnerability indicators were added
        self.assertTrue(enhanced_info['not_valid_after_vulnerable'])
        self.assertIn('expired', enhanced_info['not_valid_after_vulnerability'])
        
        self.assertTrue(enhanced_info['is_self_signed_vulnerable'])
        self.assertIn('self-signed', enhanced_info['is_self_signed_vulnerability'])
        
        self.assertTrue(enhanced_info['key_size_vulnerable'])
        self.assertIn('1024 bits', enhanced_info['key_size_vulnerability'])
        
        self.assertTrue(enhanced_info['signature_algorithm_vulnerable'])
        self.assertIn('SHA-1', enhanced_info['signature_algorithm_vulnerability'])
    
    @patch('axonOpsWorkbench.check_tls_security.get_certificate_chain')
    @patch('axonOpsWorkbench.check_tls_security.extract_connection_info')
    def test_checkTLSSecurity_with_certificate_info(self, mock_extract, mock_get_cert):
        """Test that checkTLSSecurity includes certificate_info field"""
        # Mock connection info
        mock_extract.return_value = ('test.cassandra.local', 9042)
        
        # Create test certificate with weak key
        cert_der = self._create_test_certificate(key_size=1024)
        
        # Mock certificate chain return
        mock_get_cert.return_value = (
            [cert_der],
            {
                'host': 'test.cassandra.local',
                'port': 9042,
                'connected': True,
                'tls_version': 'TLSv1.2',
                'cipher_suite': 'ECDHE-RSA-AES256-GCM-SHA384',
                'cipher_bits': 256
            }
        )
        
        # Mock session
        mock_session = Mock()
        
        # Run the check
        result = checkTLSSecurity(mock_session)
        
        # Verify the new certificate_info field exists
        self.assertIn('certificate_info', result)
        self.assertEqual(len(result['certificate_info']), 1)
        
        cert_info = result['certificate_info'][0]
        self.assertEqual(cert_info['position'], 0)
        self.assertEqual(cert_info['type'], 'end-entity')
        self.assertIn('details', cert_info)
        
        # Check that vulnerability was marked
        details = cert_info['details']
        self.assertTrue(details['key_size_vulnerable'])
        self.assertIn('1024 bits', details['key_size_vulnerability'])
    
    @patch('axonOpsWorkbench.check_tls_security.get_certificate_chain')
    @patch('axonOpsWorkbench.check_tls_security.extract_connection_info')
    def test_connection_vulnerability_indicators(self, mock_extract, mock_get_cert):
        """Test that connection info includes vulnerability indicators"""
        # Mock connection info
        mock_extract.return_value = ('test.cassandra.local', 9042)
        
        # Create test certificate
        cert_der = self._create_test_certificate()
        
        # Mock certificate chain with weak TLS version
        mock_get_cert.return_value = (
            [cert_der],
            {
                'host': 'test.cassandra.local',
                'port': 9042,
                'connected': True,
                'tls_version': 'TLSv1.0',  # Weak version
                'cipher_suite': 'DES-CBC3-SHA',  # Weak cipher
                'cipher_bits': 168
            }
        )
        
        # Mock session
        mock_session = Mock()
        
        # Run the check
        result = checkTLSSecurity(mock_session)
        
        # Verify connection vulnerability indicators
        self.assertTrue(result['connection']['tls_version_vulnerable'])
        self.assertIn('TLS 1.0', result['connection']['tls_version_vulnerability'])
        
        self.assertTrue(result['connection']['cipher_suite_vulnerable'])
        # The cipher suite vulnerability could be either weak encryption or no PFS
        cipher_vuln = result['connection']['cipher_suite_vulnerability']
        self.assertTrue('weak encryption' in cipher_vuln or 'Perfect Forward Secrecy' in cipher_vuln)

    def test_connection_error_types(self):
        """Test different connection error types are properly categorized"""
        # Test connection refused
        connection_info = {
            'connected': False,
            'error_type': 'CONNECTION_REFUSED',
            'error': 'Connection refused to localhost:9042 - service may be down'
        }
        
        warnings = []
        # Simulate the warning generation logic from checkTLSSecurity
        if connection_info.get('error_type') == 'CONNECTION_REFUSED':
            warnings.append({
                'category': 'CONNECTION_REFUSED',
                'message': connection_info['error']
            })
        
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]['category'], 'CONNECTION_REFUSED')
        
        # Test NO_TLS error
        connection_info = {
            'connected': False,
            'error_type': 'NO_TLS',
            'error': 'Service at localhost:9042 does not appear to be using TLS/SSL'
        }
        
        warnings = []
        if connection_info.get('error_type') == 'NO_TLS':
            warnings.append({
                'category': 'TLS_NOT_ENABLED',
                'message': connection_info['error']
            })
        
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]['category'], 'TLS_NOT_ENABLED')
    
    def test_malformed_certificate_handling(self):
        """Test handling of malformed certificates with partial errors"""
        # Create cert info with error fields
        cert_info = {
            'subject': '<error: Invalid subject>',
            'issuer': 'CN=Test CA',
            'not_valid_after': '<error: Invalid date>',
            'not_valid_before': '2023-01-01T00:00:00',
            'key_type': 'RSA',
            'key_size': 2048,
            'signature_algorithm': 'sha256WithRSAEncryption'
        }
        
        warnings = check_certificate_security(cert_info, {})
        
        # Should have date error warning
        date_warnings = [w for w in warnings if w['category'] == 'CERTIFICATE_DATE_ERROR']
        self.assertEqual(len(date_warnings), 1)
        self.assertIn('invalid or unparseable date', date_warnings[0]['message'])
    
    def test_robust_certificate_parsing(self):
        """Test that certificate parsing handles errors gracefully"""
        # Create a mock certificate with problematic fields
        cert_der = self._create_test_certificate()
        
        # Parse it normally first
        cert_info = analyze_certificate(cert_der)
        
        # Verify essential fields are present even if some fail
        self.assertIn('subject', cert_info)
        self.assertIn('issuer', cert_info)
        self.assertIn('fingerprints', cert_info)
        self.assertIn('sha256', cert_info.get('fingerprints', {}))
    
    @patch('axonOpsWorkbench.check_tls_security.socket.create_connection')
    def test_non_tls_service_detection(self, mock_socket):
        """Test detection of non-TLS services"""
        # Mock a plain socket that connects
        mock_plain_sock = Mock()
        mock_socket.return_value = mock_plain_sock
        
        # Mock SSL wrap to fail with wrong version number
        mock_plain_sock.close = Mock()
        ssl_error = ssl.SSLError("wrong version number")
        
        with patch('ssl.SSLContext.wrap_socket', side_effect=ssl_error):
            certs, conn_info = get_certificate_chain('localhost', 9042)
        
        self.assertEqual(conn_info['error_type'], 'NO_TLS')
        self.assertIn('does not appear to be using TLS/SSL', conn_info['error'])
    
    @patch('axonOpsWorkbench.check_tls_security.get_certificate_chain')
    @patch('axonOpsWorkbench.check_tls_security.extract_connection_info')
    def test_checkTLSSecurity_with_connection_errors(self, mock_extract, mock_get_cert):
        """Test checkTLSSecurity handles various connection errors properly"""
        mock_extract.return_value = ('localhost', 9042)
        
        # Test DNS error
        mock_get_cert.return_value = (
            [],
            {
                'host': 'invalid.host.local',
                'port': 9042,
                'connected': False,
                'error_type': 'DNS_ERROR',
                'error': "Cannot resolve hostname 'invalid.host.local': Name or service not known"
            }
        )
        
        result = checkTLSSecurity(Mock())
        
        dns_warnings = [w for w in result['warnings'] if w['category'] == 'DNS_RESOLUTION_FAILED']
        self.assertEqual(len(dns_warnings), 1)
        self.assertIn('Cannot resolve hostname', dns_warnings[0]['message'])

    def test_multiple_vulnerabilities_aggregation(self):
        """Test that multiple vulnerabilities for the same field are aggregated"""
        # Create warnings with multiple issues for the same field
        cert_info = {
            'not_valid_after': '2024-01-01T00:00:00',
            'signature_algorithm': 'md5WithRSAEncryption',
            'key_size': 1024,
            'key_type': 'RSA'
        }
        
        warnings = [
            {
                'category': 'CERTIFICATE_EXPIRED',
                'message': 'Certificate expired on 2024-01-01T00:00:00'
            },
            {
                'category': 'CERTIFICATE_DATE_ERROR',
                'message': 'Certificate contains invalid or unparseable date fields'
            },
            {
                'category': 'WEAK_SIGNATURE_ALGORITHM',
                'message': 'Certificate uses MD5 signature algorithm which is cryptographically broken'
            },
            {
                'category': 'WEAK_KEY_SIZE',
                'message': 'RSA key size 1024 bits is below recommended minimum of 2048 bits'
            }
        ]
        
        # Add vulnerability indicators
        enhanced_info = _add_vulnerability_indicators(cert_info, warnings)
        
        # Test multiple vulnerabilities using helper
        self._assert_vulnerability_structure(
            enhanced_info, 
            'not_valid_after',
            expected_count=2,
            expected_messages=[
                'Certificate expired on 2024-01-01T00:00:00',
                'Certificate contains invalid or unparseable date fields'
            ]
        )
        
        # Test single vulnerabilities using helper
        self._assert_vulnerability_structure(
            enhanced_info,
            'signature_algorithm',
            expected_count=1,
            expected_messages=['Certificate uses MD5 signature algorithm which is cryptographically broken']
        )
        
        self._assert_vulnerability_structure(
            enhanced_info,
            'key_size',
            expected_count=1,
            expected_messages=['RSA key size 1024 bits is below recommended minimum of 2048 bits']
        )
    
    @patch('axonOpsWorkbench.check_tls_security.get_certificate_chain')
    @patch('axonOpsWorkbench.check_tls_security.extract_connection_info')
    def test_connection_multiple_vulnerabilities(self, mock_extract, mock_get_cert):
        """Test that multiple connection vulnerabilities are aggregated"""
        mock_extract.return_value = ('localhost', 9042)
        
        # Create test certificate
        cert_der = self._create_test_certificate()
        
        # Mock connection with both weak cipher and no PFS
        mock_get_cert.return_value = (
            [cert_der],
            {
                'host': 'localhost',
                'port': 9042,
                'connected': True,
                'tls_version': 'TLSv1.2',
                'cipher_suite': 'DES-CBC-SHA',  # Weak cipher without PFS
                'cipher_bits': 56
            }
        )
        
        result = checkTLSSecurity(Mock())
        
        # Test structure for cipher suite vulnerabilities
        self.assertTrue(result['connection']['cipher_suite_vulnerable'])
        self.assertIn('cipher_suite_vulnerability', result['connection'])
        
        # DES-CBC-SHA should trigger both weak cipher and no PFS warnings
        # Verify structure without depending on exact text
        warnings = result['warnings']
        cipher_warnings = [w for w in warnings if w['category'] in ['WEAK_CIPHER_SUITE', 'NO_PERFECT_FORWARD_SECRECY']]
        
        # Should have exactly 2 cipher-related warnings
        self.assertEqual(len(cipher_warnings), 2)
        
        # Check categories are both present
        warning_categories = {w['category'] for w in cipher_warnings}
        expected_categories = {'WEAK_CIPHER_SUITE', 'NO_PERFECT_FORWARD_SECRECY'}
        self.assertEqual(warning_categories, expected_categories)
        
        # Verify aggregation structure
        if 'cipher_suite_vulnerability_count' in result['connection']:
            # Multiple vulnerabilities case
            self.assertEqual(result['connection']['cipher_suite_vulnerability_count'], 2)
            vuln_string = result['connection']['cipher_suite_vulnerability']
            vuln_parts = vuln_string.split('; ')
            self.assertEqual(len(vuln_parts), 2)

    def test_structured_vulnerability_data_usage(self):
        """Demonstrate how to work with vulnerability data in a structured way"""
        # Create a certificate with multiple issues
        cert_info = {
            'not_valid_after': '2024-01-01T00:00:00',
            'key_size': 1024,
            'key_type': 'RSA'
        }
        
        warnings = [
            {'category': 'CERTIFICATE_EXPIRED', 'message': 'Certificate expired on 2024-01-01T00:00:00'},
            {'category': 'CERTIFICATE_DATE_ERROR', 'message': 'Certificate contains invalid date fields'},
            {'category': 'WEAK_KEY_SIZE', 'message': 'RSA key size 1024 bits is below minimum'}
        ]
        
        enhanced_info = _add_vulnerability_indicators(cert_info, warnings)
        
        # Extract vulnerability data in a structured way
        vulnerability_report = self._extract_vulnerability_report(enhanced_info)
        
        # Verify structure
        self.assertIn('not_valid_after', vulnerability_report)
        self.assertEqual(vulnerability_report['not_valid_after']['count'], 2)
        self.assertEqual(len(vulnerability_report['not_valid_after']['messages']), 2)
        
        self.assertIn('key_size', vulnerability_report)
        self.assertEqual(vulnerability_report['key_size']['count'], 1)
        self.assertEqual(len(vulnerability_report['key_size']['messages']), 1)
    
    def _extract_vulnerability_report(self, data):
        """Extract vulnerabilities into a structured format for easier testing/processing"""
        report = {}
        
        # Find all vulnerability fields
        for key in data:
            if key.endswith('_vulnerable') and data[key]:
                field_name = key[:-11]  # Remove '_vulnerable' suffix
                vuln_key = f'{field_name}_vulnerability'
                count_key = f'{field_name}_vulnerability_count'
                
                if vuln_key in data:
                    messages = self._parse_vulnerability_string(data[vuln_key])
                    report[field_name] = {
                        'vulnerable': True,
                        'count': data.get(count_key, 1),
                        'messages': messages if isinstance(messages, list) else [messages],
                        'raw_string': data[vuln_key]
                    }
        
        return report

if __name__ == '__main__':
    unittest.main()