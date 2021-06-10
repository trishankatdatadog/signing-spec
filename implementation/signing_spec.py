r"""Reference implementation of signing-spec.

Copyright 2021 Google LLC.
SPDX-License-Identifier: Apache-2.0
"""

import base64, binascii, dataclasses, json, struct

# Protocol requires Python 3.8+.
from typing import Dict, List, Protocol, Set


class Signer(Protocol):
    def sign(self, message: bytes) -> tuple[str, bytes]:
        """Returns the keyid of the signer, and the signature of `message`."""
        ...


class Verifier(Protocol):
    def verify(self, message: bytes, keyid: str, signature: bytes) -> bool:
        """Returns true if `message` was signed by `signature`."""
        ...


# Collection of verifiers, each of which is associated with a keyid.
Verifiers = Dict[str, Verifier]


@dataclasses.dataclass
class VerifiedPayload:
    payloadType: str
    payload: bytes
    recognizedSigners: Set[str]  # Set of keyids of signers


def b64enc(m: bytes) -> str:
    return base64.standard_b64encode(m).decode('utf-8')


def b64dec(m: str) -> bytes:
    m = m.encode('utf-8')
    try:
        return base64.b64decode(m, validate=True)
    except binascii.Error:
        return base64.b64decode(m, altchars='-_', validate=True)


def PAE(payloadType: str, payload: bytes) -> bytes:
    return b'DSSEv1 %d %b %d %b' % (
            len(payloadType), payloadType.encode('utf-8'),
            len(payload), payload)


def Sign(payloadType: str, payload: bytes, signer: Signer) -> str:
    keyid, sig = signer.sign(PAE(payloadType, payload))
    return json.dumps({
        'payload': b64enc(payload),
        'payloadType': payloadType,
        'signatures': [{
            'keyid': keyid,
            'sig': b64enc(sig),
        }],
    })


def Verify(json_signature: str, verifiers: Verifiers) -> VerifiedPayload:
    wrapper = json.loads(json_signature)
    payloadType = wrapper['payloadType']
    payload = b64dec(wrapper['payload'])
    pae = PAE(payloadType, payload)
    recognizedSigners = set()
    for signature in wrapper['signatures']:
        keyid, sig = signature['keyid'], signature['sig']
        verifier = verifiers.get(keyid)
        if verifier and verifier.verify(pae, keyid, b64dec(sig)):
            recognizedSigners.add(keyid)
    if not recognizedSigners:
        raise ValueError('No valid signature found')
    return VerifiedPayload(payloadType, payload, recognizedSigners)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
