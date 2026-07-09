from pysrphard import create_verifier, validate_verifier, SRPClient, SRPServer, calculate_M, \
    calculate_HAMK, BadRecordMAC, IllegalParameter, pad_int, SRP_GROUP_PARAMETERS
import unittest
import hashlib
import random
import os

class ClientServerTests(unittest.TestCase):
    def test_auth_pbkdf2(self):
        user_identity = b'testuser@ryanhopkins.dev'
        password = b'password'

        v, s = create_verifier(
            user_identity, 
            password, 
            hashlib.pbkdf2_hmac, 
            { 
                'hash_name': 'sha256' , 
                'iterations': 1000 
            },
            srp_group_bits=2048
        )

        validate_verifier(v, srp_group_bits=2048)

        self.assertEqual(len(s), 16)
        self.assertEqual(len(v), 256)

        A, a = SRPClient.start_key_exchange(srp_group_bits=2048)

        B, server_K = SRPServer.key_exchange(v, A, srp_group_bits=2048)

        client_M, client_K = SRPClient.finish_key_exchange(
            user_identity, 
            password, 
            s, 
            A, 
            a, 
            B,
            hashlib.pbkdf2_hmac, 
            { 
                'hash_name': 'sha256', 
                'iterations': 1000 
            },
            srp_group_bits=2048
        )

        server_hamk = SRPServer.authenticate_client(user_identity, s, A, B, client_M, server_K, srp_group_bits=2048)

        SRPClient.authenticate_server(A, client_M, server_hamk, client_K, srp_group_bits=2048)

        client_hamk = calculate_HAMK(A, client_M, client_K, srp_group_bits=2048)
        server_M = calculate_M(user_identity, s, A, B, server_K, srp_group_bits=2048)

        self.assertEqual(client_K, server_K)
        self.assertEqual(client_M, server_M)
        self.assertEqual(server_hamk, client_hamk)

    def test_incorrect_password_pbkdf2(self):
        user_identity = os.urandom(128)
        correct_password = os.urandom(128)
        incorrect_password = b'passw0rd'

        v, s = create_verifier(
            user_identity, 
            correct_password, 
            hashlib.pbkdf2_hmac, 
            { 
                'hash_name': 'sha256' , 
                'iterations': 1000 
            },
            srp_group_bits=2048
        )

        validate_verifier(v, srp_group_bits=2048)

        self.assertEqual(len(s), 16)
        self.assertEqual(len(v), 256)

        A, a = SRPClient.start_key_exchange(srp_group_bits=2048)

        B, server_K = SRPServer.key_exchange(v, A, srp_group_bits=2048)

        client_M, client_K = SRPClient.finish_key_exchange(
            user_identity, 
            incorrect_password, 
            s, 
            A, 
            a, 
            B,
            hashlib.pbkdf2_hmac, 
            { 
                'hash_name': 'sha256', 
                'iterations': 1000 
            },
            srp_group_bits=2048
        )

        with self.assertRaises(BadRecordMAC):
            SRPServer.authenticate_client(user_identity, s, A, B, client_M, server_K, srp_group_bits=2048)

        server_M = calculate_M(user_identity, s, A, B, server_K, srp_group_bits=2048)
        server_hamk = calculate_HAMK(A, server_M, server_K, srp_group_bits=2048)
        client_hamk = calculate_HAMK(A, client_M, client_K, srp_group_bits=2048)

        with self.assertRaises(BadRecordMAC):
            SRPClient.authenticate_server(A, client_M, server_hamk, client_K, srp_group_bits=2048)

        self.assertNotEqual(client_K, server_K)
        self.assertNotEqual(client_M, server_M)
        self.assertNotEqual(server_hamk, client_hamk)

    def test_illegal_parameters_scrypt(self):
        user_identity = b'testuser2@ryanhopkins.dev'
        password = os.urandom(32)

        v, s = create_verifier(
            user_identity, 
            password, 
            hashlib.scrypt, 
            { 
                'n': 2, 
                'r': 1,
                'p': 1
            },
            srp_group_bits=2048
        )

        validate_verifier(v, srp_group_bits=2048)

        self.assertEqual(len(s), 16)
        self.assertEqual(len(v), 256)

        with self.assertRaises(KeyError):
            SRPClient.start_key_exchange(srp_group_bits=1024)

        A, a = SRPClient.start_key_exchange(srp_group_bits=2048)

        with self.assertRaises(IllegalParameter):
            SRPServer.key_exchange(v, pad_int(0, 2048), srp_group_bits=2048)
        
        srp_group = SRP_GROUP_PARAMETERS[2048]

        with self.assertRaises(IllegalParameter):
            SRPServer.key_exchange(v, pad_int(srp_group.N, 2048), srp_group_bits=2048)

        with self.assertRaises(OverflowError):
            r = random.randint(2, 255)
            n = srp_group.N * r
            SRPServer.key_exchange(v, pad_int(n, (n.bit_length() + 7) // 8), srp_group_bits=2048)

        B, server_K = SRPServer.key_exchange(v, A, srp_group_bits=2048)

        with self.assertRaises(IllegalParameter):
            SRPClient.finish_key_exchange(
                user_identity, 
                password, 
                s, 
                A, 
                a, 
                pad_int(0, 2048),
                hashlib.scrypt, 
                {
                    'n': 2, 
                    'r': 1,
                    'p': 1
                },
                srp_group_bits=2048
            )
        
        with self.assertRaises(IllegalParameter):
            SRPClient.finish_key_exchange(
                user_identity, 
                password, 
                s, 
                pad_int(srp_group.N, 2048), 
                a, 
                B,
                hashlib.scrypt, 
                { 
                    'n': 2, 
                    'r': 1,
                    'p': 1
                },
                srp_group_bits=2048
            )
        
        client_M, client_K = SRPClient.finish_key_exchange(
            user_identity, 
            password, 
            s, 
            A, 
            a, 
            B,
            hashlib.scrypt, 
            { 
                'n': 2, 
                'r': 1,
                'p': 1
            },
            srp_group_bits=2048
        )

        with self.assertRaises(IllegalParameter):
            calculate_M(user_identity, s, pad_int(0, 2048), B, server_K, srp_group_bits=2048)

        with self.assertRaises(IllegalParameter):
            calculate_M(user_identity, s, A, pad_int(0, 2048), server_K, srp_group_bits=2048)
        
        server_M = calculate_M(user_identity, s, A, B, server_K, srp_group_bits=2048)

        with self.assertRaises(IllegalParameter):
            calculate_HAMK(pad_int(0, 2048), server_M, server_K, srp_group_bits=2048)

        server_hamk = calculate_HAMK(A, server_M, server_K, srp_group_bits=2048)
        client_hamk = calculate_HAMK(A, client_M, client_K, srp_group_bits=2048)

        self.assertEqual(client_K, server_K)
        self.assertEqual(client_M, server_M)
        self.assertEqual(server_hamk, client_hamk)
