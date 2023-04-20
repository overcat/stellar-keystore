import json
import unittest

from stellar_sdk import Keypair

from stellar_keystore import *


class TestStellarKeystore(unittest.TestCase):
    def test_load_keystore(self):
        keystore = {
            "version": "stellarport-1-20-2018",
            "address": "GCF3PTYFRIHTIR2W5OJIBWEYBFYB4MIQJGFMG3WWQ2BRMPZE2SWPXYVF",
            "crypto": {
                "ciphertext": "7UykVnO+U8uWFZylirEde0arotr/Oi3qRZFfBsbUz2O/ad8ON+xT8KFltZAS+eWuCsx1QyU03Pfgo1E4N/BcIylf2d9emw/b",
                "nonce": "Yrd0mu0MPBYOI1ZC8eRnIWLaaEzJV+kS",
                "salt": "9GcuyHxDft6w6GZmAfOhoL/pluU/DhNwRftiQKjX1Lw=",
                "scryptOptions": {
                    "N": 16384,
                    "r": 8,
                    "p": 1,
                    "dkLen": 32,
                    "encoding": "binary",
                },
            },
        }
        expected_kp = Keypair.from_secret(
            "SBVWNNC7VQIG32L3DGPXVSQK25JNFZGZMNQB43RQBCZC55YQ553AME37"
        )
        kp = load_keystore(keystore, b"pAsswOrd")
        self.assertEqual(kp, expected_kp)

    def test_create_keystore(self):
        pwd = b"pAsswOrd!!!"
        kp0 = Keypair.random()
        keystore = create_keystore(kp0, pwd)
        kp1 = load_keystore(keystore, pwd)
        self.assertEqual(kp0, kp1)

    def test_keystore_serializable(self):
        pwd = b"pAsswOrd!!!"
        kp0 = Keypair.random()
        keystore = create_keystore(kp0, pwd)
        keystore_str = json.dumps(keystore)
        keystore_dict = json.loads(keystore_str)
        self.assertEqual(keystore, keystore_dict)
