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
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from cqlshlib.axonOpsWorkbench.check_tls_security import (
    extract_connection_info,
    analyze_certificate,
    check_certificate_security,
    check_tls_security,
    checkTLSSecurityBackground,
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
        self.assertIn('Failed to parse certificate', cert_info['error'])
    
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
        self.assertIn('20 days', expiry_warnings[0]['message'])
    
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
        # Certificate with SHA1 signature
        cert_der = self._create_test_certificate(signature_hash=hashes.SHA1())
        
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
    
    @patch('cqlshlib.axonOpsWorkbench.check_tls_security.extract_connection_info')
    @patch('cqlshlib.axonOpsWorkbench.check_tls_security.get_certificate_chain')
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
    
    @patch('cqlshlib.axonOpsWorkbench.check_tls_security.extract_connection_info')
    @patch('cqlshlib.axonOpsWorkbench.check_tls_security.get_certificate_chain')
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
        
        self.assertEqual(result['status'], 'success')  # Function completed successfully
        connection_warnings = [w for w in result['warnings'] if w['category'] == 'CONNECTION_FAILED']
        self.assertEqual(len(connection_warnings), 1)
        self.assertIn('Connection refused', connection_warnings[0]['message'])
    
    @patch('cqlshlib.axonOpsWorkbench.check_tls_security.extract_connection_info')
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
        analysis_warnings = [w for w in result['warnings'] if w['category'] == 'ANALYSIS_ERROR']
        self.assertEqual(len(analysis_warnings), 1)


if __name__ == '__main__':
    unittest.main()