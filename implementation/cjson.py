#!/usr/bin/env python

import binascii
import json

from securesystemslib.keys import create_signature, verify_signature
from securesystemslib.formats import encode_canonical

from signing_spec import Sign, Verify, b64dec


PAYLOAD_TYPE = 'https://github.com/secure-systems-lab/securesystemslib'

KEY1 = {
    'keytype': 'ed25519',
    'scheme': 'ed25519',
    'keyid': '726452f9f3aab8699511957f0d090f27b95089efcecc0ce49cc846cb41939f03',
    'keyid_hash_algorithms': ['sha256', 'sha512'],
    'keyval': {
        'public': '0eba66da7021af0f14f262ab6ebaa5aefe93b6bc452e92619bc989cd68a298ed',
        'private': 'b27a1c78764639522eac3cb8528b56db38e2ff114f746a19fa514ffa92e995fb'
    }
}

KEY2 = {
    'keytype': 'ed25519',
    'scheme': 'ed25519',
    'keyid': '20468fe4f6cb3321a5e9e0f744f63d1bd780aec5f3b3e3f2985ee2d6804b0cb6',
    'keyid_hash_algorithms': ['sha256', 'sha512'],
    'keyval': {
        'public': '7d942cf22f9fd96a00dee133993e88e96314a8f7979ab5c49ca66ea7800c6ce2',
        'private': '0aa8d3113c663870ec55a68712a882195aae8bcf663384377485541e293054bd'
    }
}

DATA = {
    "_type": "timestamp",
    "expires": "2030-01-01T00:00:00Z",
    "meta": {
        "snapshot.json": {
            "hashes": {
                "sha256": "8f88e2ba48b412c3843e9bb26e1b6f8fc9e98aceb0fbaa97ba37b4c98717d7ab"
            },
            "length": 515,
            "version": 1
        }
    },
    "spec_version": "1.0.0",
    "version": 1
}


class Signer:
    def __init__(self, key):
        self.key = key

    def sign(self, message: bytes) -> tuple[str, bytes]:
        wrapper = create_signature(self.key, message)
        return wrapper['keyid'], wrapper['sig'].encode('utf-8')


class Verifier:
    def __init__(self, key):
        self.key = key

    def verify(self, message: bytes, keyid: str, signature: bytes) -> bool:
        sig = {
            'keyid': keyid,
            'sig': signature.decode('utf-8'),
        }
        return verify_signature(self.key, sig, message)


if __name__ == '__main__':
    # issue signatures
    payload1 = encode_canonical(DATA).encode('utf-8')
    sig1 = json.loads(Sign(PAYLOAD_TYPE, payload1, Signer(KEY1)))
    sig2 = json.loads(Sign(PAYLOAD_TYPE, payload1, Signer(KEY2)))

    # collate signatures
    assert sig1['payload'] == sig2['payload']
    assert sig1['payloadType'] == sig2['payloadType']
    assert sig1['signatures'] != sig2['signatures']
    sig = sig1.copy()
    sig['signatures'].extend(sig2['signatures'])
    assert len(sig['signatures']) == 2
    assert KEY1['keyid'] == sig['signatures'][0]['keyid']
    assert KEY2['keyid'] == sig['signatures'][1]['keyid']
    print(json.dumps(sig, indent=4, sort_keys=True))
    print()

    # threshold verifiers
    verifiers = {
        KEY1['keyid']: Verifier(KEY1),
        KEY2['keyid']: Verifier(KEY2),
    }
    verified = Verify(json.dumps(sig), verifiers)
    assert len(verified.recognizedSigners) == 2
    assert KEY1['keyid'] in verified.recognizedSigners
    assert KEY2['keyid'] in verified.recognizedSigners

    # safely decode payload now that we have authenticated its type
    data = json.loads(b64dec(sig['payload']))
    assert data == DATA
    print(json.dumps(data, indent=4, sort_keys=True))
