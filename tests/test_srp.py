from pysrphard import create_verifier, validate_verifier, SRPClient, SRPServer, calculate_M, calculate_u, \
    calculate_HAMK, BadRecordMAC, IllegalParameter, pad_int, SRP_GROUP_PARAMETERS, SRPGroup
import unittest
import hashlib
import random
import os

class SRPTests(unittest.TestCase):
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
        SRPServer.validate_verifier(v, srp_group_bits=2048)

        self.assertEqual(len(s), 32)
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

    def test_auth_scrypt(self):
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
        SRPServer.validate_verifier(v, srp_group_bits=2048)

        self.assertEqual(len(s), 32)
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
            hashlib.scrypt, 
            { 
                'n': 2, 
                'r': 1,
                'p': 1
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
                'hash_name': 'sha256',
                'iterations': 1000
            },
            srp_group_bits=2048
        )

        validate_verifier(v, srp_group_bits=2048)
        SRPServer.validate_verifier(v, srp_group_bits=2048)

        self.assertEqual(len(s), 32)
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

    def test_illegal_parameters_pbkdf2(self):
        user_identity = b'testuser3'
        password = b''

        v, s = create_verifier(
            user_identity, 
            password, 
            hashlib.pbkdf2_hmac, 
            { 
                'hash_name': 'sha256', 
                'iterations': 1000 
            },
            srp_group_bits=2048
        )

        validate_verifier(v, srp_group_bits=2048)
        SRPServer.validate_verifier(v, srp_group_bits=2048)

        self.assertEqual(len(s), 32)
        self.assertEqual(len(v), 256)

        with self.assertRaises(KeyError):
            SRPClient.start_key_exchange(srp_group_bits=1024)

        A, a = SRPClient.start_key_exchange(srp_group_bits=2048)

        with self.assertRaises(IllegalParameter):
            SRPServer.key_exchange(v, pad_int(0, 256), srp_group_bits=2048)
        
        srp_group = SRP_GROUP_PARAMETERS[2048]
        
        with self.assertRaises(IllegalParameter):
            SRPServer.key_exchange(v, pad_int(srp_group.N, 256), srp_group_bits=2048)

        with self.assertRaises(IllegalParameter):
            SRPServer.key_exchange(pad_int(0, 256), A, srp_group_bits=2048)

        with self.assertRaises(IllegalParameter):
            SRPServer.key_exchange(pad_int(1, 256), A, srp_group_bits=2048)

        with self.assertRaises(IllegalParameter):
            SRPServer.key_exchange(pad_int(srp_group.N-1, 256), A, srp_group_bits=2048)
        
        with self.assertRaises(IllegalParameter):
            SRPServer.key_exchange(pad_int(srp_group.N, 256), A, srp_group_bits=2048)

        with self.assertRaises(IllegalParameter):
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
                pad_int(0, 256),
                hashlib.pbkdf2_hmac, 
                { 
                    'hash_name': 'sha256', 
                    'iterations': 1000 
                },
                srp_group_bits=2048
            )
        
        with self.assertRaises(IllegalParameter):
            SRPClient.finish_key_exchange(
                user_identity, 
                password, 
                s, 
                pad_int(srp_group.N, 256), 
                a, 
                B,
                hashlib.pbkdf2_hmac, 
                { 
                    'hash_name': 'sha256', 
                    'iterations': 1000 
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
            hashlib.pbkdf2_hmac, 
            { 
                'hash_name': 'sha256', 
                'iterations': 1000 
            },
            srp_group_bits=2048
        )

        server_M = calculate_M(user_identity, s, A, B, server_K, srp_group_bits=2048)
        calculated_server_hamk = calculate_HAMK(A, server_M, server_K, srp_group_bits=2048)
        client_hamk = calculate_HAMK(A, client_M, client_K, srp_group_bits=2048)

        self.assertEqual(client_K, server_K)
        self.assertEqual(client_M, server_M)
        self.assertEqual(calculated_server_hamk, client_hamk)

        with self.assertRaises(IllegalParameter):
            SRPServer.authenticate_client(
                user_identity,
                s,
                pad_int(0, 256),
                B,
                client_M,
                server_K,
                2048
            )

        server_hamk = SRPServer.authenticate_client(
            user_identity,
            s,
            A,
            B,
            client_M,
            server_K,
            2048
        )

        with self.assertRaises(IllegalParameter):
            SRPClient.authenticate_server(
                pad_int(0, 256),
                client_M,
                server_hamk,
                client_K,
                2048
            )

        SRPClient.authenticate_server(
            A,
            client_M,
            server_hamk,
            client_K,
            2048
        )

    def test_rfc_vectors(self):
        N = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
        g = 2

        SRP_GROUP_PARAMETERS[1024] = SRPGroup(1024, N, g, 128)

        try:
            user_identity = b'alice'
            password = b'password123'

            rfc_hash = hashlib.sha1
            rfc_kdf = lambda password, salt: rfc_hash(salt + rfc_hash(password).digest()).digest()

            a_int = 0x60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393
            b_int = 0xE487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20

            A = pad_int(SRPClient.calculate_A(a_int, 1024), 128)
            expected_A = 0x61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B

            self.assertEqual(A, pad_int(expected_A, 128))

            s = 0xBEB25379D1A8581EB5A727673A2441EE.to_bytes(16, byteorder='big')

            v, _ = create_verifier(
                user_identity, 
                password,
                rfc_kdf,
                {},
                1024,
                s
            )

            expected_v = 0x7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB

            self.assertEqual(v, pad_int(expected_v, 128))

            B = pad_int(SRPServer.calculate_B(b_int, v, 1024, rfc_hash), 128)

            expected_B = 0xBD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58

            self.assertEqual(B, pad_int(expected_B, 128))

            u = calculate_u(A, B, rfc_hash)

            expected_u = 0xCE38B9593487DA98554ED47D70A7AE5F462EF019

            self.assertEqual(pad_int(u, rfc_hash().digest_size), pad_int(expected_u, rfc_hash().digest_size))

            expected_premaster_secret = 0xB0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A

            a = pad_int(a_int, 32)
            b = pad_int(b_int, 32)

            client_secret = SRPClient.calculate_client_secret(
                user_identity, 
                password,
                s,
                a,
                A,
                B,
                rfc_kdf,
                {},
                1024,
                rfc_hash
            )

            self.assertEqual(client_secret, pad_int(expected_premaster_secret, 128))

            server_secret = SRPServer.calculate_server_secret(
                v,
                b,
                B,
                A,
                1024,
                rfc_hash
            )

            self.assertEqual(server_secret, pad_int(expected_premaster_secret, 128))

        finally:
            del SRP_GROUP_PARAMETERS[1024]
