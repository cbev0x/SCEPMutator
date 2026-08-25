# -*- coding: utf-8 -*-
"""
scep_core - SCEP protocol construction & parsing for SCEPMutator.

Builds the enrollment pipeline stage by stage so each is an independent mutation
point for the differential probes:

    signer keypair  ->  inner PKCS#10  ->  EnvelopedData (pkcsPKIEnvelope)
    ->  SignedData + SCEP authenticated attributes  ->  PKIMessage

CSRs are assembled with asn1crypto (not cryptography's builder) so the
challengePassword ASN.1 string type and requested SANs are fully controllable
(challenge encoding is the NDES `nombstr` axis; SAN is cell 7.1).

Nothing here does I/O; the transport + CLI live in scepmutator.py.
"""

import os
import hashlib
import datetime

from asn1crypto import cms, csr, x509, keys, core, algos, parser

from cryptography import x509 as c_x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # older cryptography
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

# --- SCEP attribute OIDs (Microsoft arc, used by every SCEP server) ---
OID_messageType   = '2.16.840.1.113733.1.9.2'
OID_pkiStatus     = '2.16.840.1.113733.1.9.3'
OID_failInfo      = '2.16.840.1.113733.1.9.4'
OID_senderNonce   = '2.16.840.1.113733.1.9.5'
OID_recipientNonce= '2.16.840.1.113733.1.9.6'
OID_transId       = '2.16.840.1.113733.1.9.7'
OID_challengePassword = '1.2.840.113549.1.9.7'
OID_extensionRequest  = '1.2.840.113549.1.9.14'

MSG_PKCSReq       = '19'
MSG_CertRep       = '3'
MSG_GetCertInitial= '20'
MSG_GetCert       = '21'
MSG_RenewalReq    = '17'

PKISTATUS = {'0': 'SUCCESS', '2': 'FAILURE', '3': 'PENDING'}
FAILINFO = {
    '0': 'badAlg', '1': 'badMessageCheck', '2': 'badRequest',
    '3': 'badTime', '4': 'badCertId',
}

_HASHES = {'sha1': hashes.SHA1, 'sha256': hashes.SHA256,
           'sha512': hashes.SHA512}
_DIGEST_OID = {'sha1': 'sha1', 'sha256': 'sha256', 'sha512': 'sha512'}


# ---------------------------------------------------------------------------
# Keys / signer cert
# ---------------------------------------------------------------------------

def gen_rsa(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def selfsigned_signer(key, cn="scepmutator"):
    """Ephemeral self-signed cert used as the outer CMS signer (SCEP requires
    the initial PKCSReq to be self-signed by a throwaway identity)."""
    name = c_x509.Name([c_x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (c_x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(c_x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# Inner PKCS#10  (asn1crypto, full field control)
# ---------------------------------------------------------------------------

def build_csr(key, common_name, challenge=None, challenge_encoding="printable",
              sans=None, digest="sha256", pop_sign_key=None):
    """Build a PKCS#10 with full control.

    challenge_encoding: 'printable' (NDES-correct) or 'utf8' (OpenSSL default,
        the NDES-reject case) -- this is the string_mask=nombstr axis.
    sans: list of ('dns'|'email'|'upn'|'ip'|'uri', value) tuples -> extensionRequest.
    pop_sign_key: if given, the CRI is signed by THIS key instead of `key`. When it
        differs from `key`, the CSR self-signature is invalid -> the inner proof-of-
        possession is broken (the requester does not hold the private key for the
        public key in the CSR). This is the inner-CSR PoP mutation.
    """
    pub = key.public_key()
    spki = keys.PublicKeyInfo.load(
        pub.public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo))

    subject = x509.Name.build({'common_name': common_name})

    attributes = []
    if challenge is not None:
        if challenge_encoding == "utf8":
            cval = core.UTF8String(challenge)
        else:
            cval = core.PrintableString(challenge)
        attributes.append(csr.CRIAttribute({
            'type': OID_challengePassword,
            'values': [cval],
        }))

    if sans:
        gnames = []
        for kind, val in sans:
            if kind == "dns":
                gnames.append(x509.GeneralName('dns_name', val))
            elif kind == "email":
                gnames.append(x509.GeneralName('rfc822_name', val))
            elif kind == "ip":
                gnames.append(x509.GeneralName('ip_address', val))
            elif kind == "uri":
                gnames.append(x509.GeneralName('uniform_resource_identifier', val))
            elif kind == "upn":
                # otherName: userPrincipalName (1.3.6.1.4.1.311.20.2.3), value UTF8String
                gnames.append(x509.GeneralName('other_name', x509.AnotherName({
                    'type_id': '1.3.6.1.4.1.311.20.2.3',
                    'value': core.UTF8String(val).retag({'explicit': 0}),
                })))
            else:
                raise ValueError("unknown SAN kind: %s" % kind)
        ext = x509.Extension({'extn_id': 'subject_alt_name',
                              'extn_value': x509.GeneralNames(gnames)})
        exts = x509.Extensions([ext])
        attributes.append(csr.CRIAttribute({
            'type': OID_extensionRequest,
            'values': [exts],
        }))

    cri = csr.CertificationRequestInfo({
        'version': 'v1',
        'subject': subject,
        'subject_pk_info': spki,
        'attributes': csr.CRIAttributes(attributes),
    })

    hfn = _HASHES[digest]()
    pop_key = pop_sign_key if pop_sign_key is not None else key
    signature = pop_key.sign(cri.dump(), padding.PKCS1v15(), hfn)
    request = csr.CertificationRequest({
        'certification_request_info': cri,
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},  # sha per digest below
        'signature': signature,
    })
    # fix sig alg to match digest
    request['signature_algorithm'] = {'algorithm': _SIG_ALG[digest]}
    return request.dump()


def build_csr_raw_subject(key, subject_name, challenge=None, digest="sha256"):
    """Like build_csr but takes an asn1crypto x509.Name directly as the subject —
    used to craft a CSR whose subject is an arbitrary DN (e.g. the CA's own subject,
    for the self-issuance confusion probe)."""
    pub = key.public_key()
    spki = keys.PublicKeyInfo.load(
        pub.public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo))
    attributes = []
    if challenge is not None:
        attributes.append(csr.CRIAttribute({
            'type': OID_challengePassword,
            'values': [core.PrintableString(challenge)],
        }))
    cri = csr.CertificationRequestInfo({
        'version': 'v1',
        'subject': subject_name,
        'subject_pk_info': spki,
        'attributes': csr.CRIAttributes(attributes),
    })
    hfn = _HASHES[digest]()
    signature = key.sign(cri.dump(), padding.PKCS1v15(), hfn)
    request = csr.CertificationRequest({
        'certification_request_info': cri,
        'signature_algorithm': {'algorithm': _SIG_ALG[digest]},
        'signature': signature,
    })
    return request.dump()


_SIG_ALG = {'sha1': 'sha1_rsa', 'sha256': 'sha256_rsa', 'sha512': 'sha512_rsa'}


# ---------------------------------------------------------------------------
# EnvelopedData  (pkcsPKIEnvelope)
# ---------------------------------------------------------------------------

def _cipher_params(cipher):
    if cipher == "aes256":
        return (32, 16, 'aes256_cbc', lambda k: algorithms.AES(k), 16)
    if cipher == "aes128":
        return (16, 16, 'aes128_cbc', lambda k: algorithms.AES(k), 16)
    if cipher == "des3":
        return (24, 8, 'tripledes_3key', lambda k: TripleDES(k), 8)
    raise ValueError("unknown cipher: %s" % cipher)


def build_enveloped(content_der, recipient_cert_der, cipher="aes256"):
    """Encrypt `content_der` (the CSR) to a recipient cert -> CMS EnvelopedData DER."""
    keylen, ivlen, algo_id, algo_fn, block = _cipher_params(cipher)
    recip = x509.Certificate.load(recipient_cert_der)

    cek = os.urandom(keylen)
    iv = os.urandom(ivlen)
    pad = block - (len(content_der) % block)
    padded = content_der + bytes([pad]) * pad
    enc = Cipher(algo_fn(cek), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()

    # RSA-wrap the CEK to the recipient public key
    recip_pub = serialization.load_der_public_key(recip.public_key.dump())
    wrapped = recip_pub.encrypt(cek, padding.PKCS1v15())

    ri = cms.RecipientInfo('ktri', cms.KeyTransRecipientInfo({
        'version': 'v0',
        'rid': cms.RecipientIdentifier('issuer_and_serial_number',
            cms.IssuerAndSerialNumber({'issuer': recip.issuer,
                                       'serial_number': recip.serial_number})),
        'key_encryption_algorithm': {'algorithm': 'rsaes_pkcs1v15'},
        'encrypted_key': wrapped,
    }))
    env = cms.EnvelopedData({
        'version': 'v0',
        'recipient_infos': [ri],
        'encrypted_content_info': {
            'content_type': 'data',
            'content_encryption_algorithm': {'algorithm': algo_id, 'parameters': iv},
            'encrypted_content': ct,
        },
    })
    return cms.ContentInfo({'content_type': 'enveloped_data', 'content': env}).dump()


def build_enveloped_with_enckey(content_der, recipient_cert_der, injected_encrypted_key,
                                cipher="aes256"):
    """Same as build_enveloped, but substitutes a caller-supplied RSA block into the
    encrypted_key field. Used by the padding-oracle probe to feed controlled PKCS#1
    v1.5 ciphertexts to the server's RSA decryption path."""
    keylen, ivlen, algo_id, algo_fn, block = _cipher_params(cipher)
    recip = x509.Certificate.load(recipient_cert_der)
    cek = os.urandom(keylen)  # real CEK is irrelevant; server never recovers it here
    iv = os.urandom(ivlen)
    pad = block - (len(content_der) % block)
    padded = content_der + bytes([pad]) * pad
    enc = Cipher(algo_fn(cek), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    ri = cms.RecipientInfo('ktri', cms.KeyTransRecipientInfo({
        'version': 'v0',
        'rid': cms.RecipientIdentifier('issuer_and_serial_number',
            cms.IssuerAndSerialNumber({'issuer': recip.issuer,
                                       'serial_number': recip.serial_number})),
        'key_encryption_algorithm': {'algorithm': 'rsaes_pkcs1v15'},
        'encrypted_key': injected_encrypted_key,
    }))
    env = cms.EnvelopedData({
        'version': 'v0',
        'recipient_infos': [ri],
        'encrypted_content_info': {
            'content_type': 'data',
            'content_encryption_algorithm': {'algorithm': algo_id, 'parameters': iv},
            'encrypted_content': ct,
        },
    })
    return cms.ContentInfo({'content_type': 'enveloped_data', 'content': env}).dump()


def craft_pkcs1_variants(recipient_cert_der, cek_len=32):
    """Craft RSA blocks with CONTROLLED PKCS#1 v1.5 structure, encrypted RAW (textbook
    RSA, no padding) to the recipient key so the *decrypted* plaintext has exactly the
    byte structure we choose. This is the Bleichenbacher/ROBOT oracle corpus: a
    conformant server MUST behave identically (indistinguishably) across all of them.

    Returns list of (name, encrypted_key_bytes, expectation).
    """
    from asn1crypto import x509 as _x
    recip = _x.Certificate.load(recipient_cert_der)
    pub = serialization.load_der_public_key(recip.public_key.dump())
    n = pub.public_numbers().n
    e = pub.public_numbers().e
    k = (n.bit_length() + 7) // 8  # modulus size in bytes

    def raw_rsa(block_int):
        c = pow(block_int, e, n)
        return c.to_bytes(k, 'big')

    def block_to_int(b):
        return int.from_bytes(b, 'big')

    variants = []

    # A CONFORMANT PKCS#1 v1.5 type-2 block: 00 02 [>=8 nonzero PS] 00 [CEK]
    ps_len = k - 3 - cek_len
    good = b'\x00\x02' + (b'\xAB' * ps_len) + b'\x00' + os.urandom(cek_len)
    variants.append(("conformant", raw_rsa(block_to_int(good)),
                     "valid padding + correct-length key -> baseline"))

    # Wrong first byte (00 -> 01): not a type-2 block at all
    bad_hdr = bytearray(good); bad_hdr[0] = 0x01
    variants.append(("bad-first-byte", raw_rsa(block_to_int(bytes(bad_hdr))),
                     "first byte != 0x00 -> invalid"))

    # Wrong block type (02 -> 01): signing block, not encryption
    bad_type = bytearray(good); bad_type[1] = 0x01
    variants.append(("bad-block-type", raw_rsa(block_to_int(bytes(bad_type))),
                     "block type != 0x02 -> invalid"))

    # No 0x00 separator anywhere after PS (fill everything nonzero)
    no_sep = b'\x00\x02' + (b'\xCD' * (k - 2))
    variants.append(("no-separator", raw_rsa(block_to_int(no_sep)),
                     "no 0x00 delimiter -> invalid padding"))

    # Separator too early (PS < 8): 00 02 [3 nonzero] 00 [rest]
    short_ps = b'\x00\x02' + (b'\xEF' * 3) + b'\x00' + os.urandom(k - 6)
    variants.append(("short-PS", raw_rsa(block_to_int(short_ps)),
                     "PS < 8 bytes -> invalid per PKCS#1"))

    # Valid padding but recovered key WRONG LENGTH (separator places a 40-byte key)
    wl = k - 3 - 40
    if wl >= 8:
        wrong_len = b'\x00\x02' + (b'\x77' * wl) + b'\x00' + os.urandom(40)
        variants.append(("valid-pad-wrong-keylen", raw_rsa(block_to_int(wrong_len)),
                         "good padding, 40-byte key (CEK-len mismatch) -> deep failure"))

    # Valid padding, separator at the very end (zero-length key)
    zero_key = b'\x00\x02' + (b'\x99' * (k - 3)) + b'\x00'
    variants.append(("valid-pad-zero-keylen", raw_rsa(block_to_int(zero_key)),
                     "good padding, empty key -> deep failure"))

    # Random garbage block (almost certainly invalid padding)
    variants.append(("random-block", raw_rsa(block_to_int(os.urandom(k)) % n),
                     "random -> invalid padding (statistically)"))

    return variants


def _iter_tlvs(buf):
    """Yield (class, method, tag, content) for each TLV in buf. parser.parse only
    decodes the first TLV and doesn't return the remainder, so advance manually."""
    rest = buf
    while rest:
        cls_, method, tag, hdr, content, _ = parser.parse(rest)
        yield cls_, method, tag, content
        rest = rest[len(hdr) + len(content):]


def _extract_encrypted_content(eci_der):
    """Given the raw DER of an EncryptedContentInfo SEQUENCE, return the
    encrypted_content octets, tolerating a constructed (BER-segmented) OCTET
    STRING (micromdm/Go) as well as a primitive one."""
    _, _, _, _, seq_content, _ = parser.parse(eci_der)
    for cls_, method, tag, content in _iter_tlvs(seq_content):
        if cls_ == 2 and tag == 0:  # [0] IMPLICIT encrypted_content
            if method == 0:
                return content
            out = b""
            for _, _, _, icontent in _iter_tlvs(content):
                out += icontent
            return out
    raise ValueError("encrypted_content not found in EncryptedContentInfo")


def decrypt_enveloped(env_der, priv_key):
    ci = cms.ContentInfo.load(env_der)
    env = ci['content']
    ri = env['recipient_infos'][0].chosen
    cek = priv_key.decrypt(ri['encrypted_key'].native, padding.PKCS1v15())
    eci = env['encrypted_content_info']
    eci_der = eci.dump()  # capture raw before spawning the encrypted_content value
    algo = eci['content_encryption_algorithm']['algorithm'].native
    iv = eci['content_encryption_algorithm']['parameters'].native
    ct = _extract_encrypted_content(eci_der)
    if algo.startswith('aes'):
        algo_fn = algorithms.AES(cek)
    elif algo in ('tripledes_3key', 'des_ede3_cbc'):
        algo_fn = TripleDES(cek)
    elif algo in ('des', 'des_cbc'):
        # single DES (micromdm envelopes its reply with 56-bit DES). cryptography
        # doesn't expose single DES, but 3DES-EDE with K1=K2=K3 is identical to it.
        algo_fn = TripleDES(cek * 3)
    else:
        raise ValueError("unsupported content cipher: %s" % algo)
    dec = Cipher(algo_fn, modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    return padded[:-padded[-1]]


# ---------------------------------------------------------------------------
# PKIMessage  (SignedData + SCEP authenticated attributes)
# ---------------------------------------------------------------------------

def build_pkcs_req(csr_der, signer_key, signer_cert_der, recipient_cert_der,
                   cipher="aes256", digest="sha256", transaction_id=None,
                   sender_nonce=None, message_type=MSG_PKCSReq,
                   sign_key=None):
    """Assemble a full SCEP PKIMessage (PKCSReq by default).

    `sign_key` defaults to `signer_key`; passing a *different* key here is the
    core identity-triangle mutation (3.5): the CMS is signed by a key that is
    not the one bound in the enclosed signer cert / CSR.
    """
    if sign_key is None:
        sign_key = signer_key
    if transaction_id is None:
        pub = signer_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        transaction_id = hashlib.sha256(pub).hexdigest()
    if sender_nonce is None:
        sender_nonce = os.urandom(16)

    envelope = build_enveloped(csr_der, recipient_cert_der, cipher=cipher)

    signer_cert = x509.Certificate.load(signer_cert_der)
    digest_oid = _DIGEST_OID[digest]
    hfn = _HASHES[digest]()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({'type': 'content_type', 'values': ['data']}),
        cms.CMSAttribute({'type': 'message_digest',
                          'values': [_digest(envelope, digest)]}),
        cms.CMSAttribute({'type': OID_transId,
                          'values': [core.PrintableString(transaction_id)]}),
        cms.CMSAttribute({'type': OID_messageType,
                          'values': [core.PrintableString(message_type)]}),
        cms.CMSAttribute({'type': OID_senderNonce,
                          'values': [core.OctetString(sender_nonce)]}),
    ])
    signature = sign_key.sign(signed_attrs.dump(), padding.PKCS1v15(), hfn)

    si = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier('issuer_and_serial_number',
            cms.IssuerAndSerialNumber({'issuer': signer_cert.issuer,
                                       'serial_number': signer_cert.serial_number})),
        'digest_algorithm': {'algorithm': digest_oid},
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': signature,
    })
    signed = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [{'algorithm': digest_oid}],
        'encap_content_info': {'content_type': 'data', 'content': envelope},
        'certificates': [signer_cert],
        'signer_infos': [si],
    })
    pki = cms.ContentInfo({'content_type': 'signed_data', 'content': signed})
    return pki.dump(), transaction_id, sender_nonce


def build_pkcs_req_with_envelope(envelope_der, signer_key, signer_cert_der,
                                 digest="sha256", transaction_id=None, sender_nonce=None,
                                 sign_key=None):
    """Build a PKCSReq PKIMessage around a PRE-BUILT EnvelopedData (used by the
    padding-oracle probe, which crafts the envelope's encrypted_key by hand)."""
    if sign_key is None:
        sign_key = signer_key
    if transaction_id is None:
        pub = signer_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        transaction_id = hashlib.sha256(pub).hexdigest()
    if sender_nonce is None:
        sender_nonce = os.urandom(16)
    signer_cert = x509.Certificate.load(signer_cert_der)
    digest_oid = _DIGEST_OID[digest]
    hfn = _HASHES[digest]()
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({'type': 'content_type', 'values': ['data']}),
        cms.CMSAttribute({'type': 'message_digest', 'values': [_digest(envelope_der, digest)]}),
        cms.CMSAttribute({'type': OID_transId, 'values': [core.PrintableString(transaction_id)]}),
        cms.CMSAttribute({'type': OID_messageType, 'values': [core.PrintableString(MSG_PKCSReq)]}),
        cms.CMSAttribute({'type': OID_senderNonce, 'values': [core.OctetString(sender_nonce)]}),
    ])
    signature = sign_key.sign(signed_attrs.dump(), padding.PKCS1v15(), hfn)
    si = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier('issuer_and_serial_number',
            cms.IssuerAndSerialNumber({'issuer': signer_cert.issuer,
                                       'serial_number': signer_cert.serial_number})),
        'digest_algorithm': {'algorithm': digest_oid},
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': signature,
    })
    signed = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [{'algorithm': digest_oid}],
        'encap_content_info': {'content_type': 'data', 'content': envelope_der},
        'certificates': [signer_cert],
        'signer_infos': [si],
    })
    return cms.ContentInfo({'content_type': 'signed_data', 'content': signed}).dump()


def build_getcert(issuer_name, serial_number, signer_key, signer_cert_der,
                  recipient_cert_der, cipher="aes256", digest="sha256",
                  transaction_id=None, sender_nonce=None, sign_key=None):
    """SCEP GetCert (messageType 21): retrieve an issued cert by issuer + serial.
    Different authz path than GetCertInitial (which is by subject). Probe: can a
    party retrieve arbitrary certs by walking serials?"""
    if sign_key is None:
        sign_key = signer_key
    if sender_nonce is None:
        sender_nonce = os.urandom(16)
    ias = cms.IssuerAndSerialNumber({'issuer': issuer_name, 'serial_number': serial_number})
    payload = ias.dump()
    if transaction_id is None:
        transaction_id = hashlib.sha256(payload).hexdigest()
    envelope = build_enveloped(payload, recipient_cert_der, cipher=cipher)
    signer_cert = x509.Certificate.load(signer_cert_der)
    digest_oid = _DIGEST_OID[digest]
    hfn = _HASHES[digest]()
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({'type': 'content_type', 'values': ['data']}),
        cms.CMSAttribute({'type': 'message_digest', 'values': [_digest(envelope, digest)]}),
        cms.CMSAttribute({'type': OID_transId, 'values': [core.PrintableString(transaction_id)]}),
        cms.CMSAttribute({'type': OID_messageType, 'values': [core.PrintableString(MSG_GetCert)]}),
        cms.CMSAttribute({'type': OID_senderNonce, 'values': [core.OctetString(sender_nonce)]}),
    ])
    signature = sign_key.sign(signed_attrs.dump(), padding.PKCS1v15(), hfn)
    si = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier('issuer_and_serial_number',
            cms.IssuerAndSerialNumber({'issuer': signer_cert.issuer,
                                       'serial_number': signer_cert.serial_number})),
        'digest_algorithm': {'algorithm': digest_oid},
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': signature,
    })
    signed = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [{'algorithm': digest_oid}],
        'encap_content_info': {'content_type': 'data', 'content': envelope},
        'certificates': [signer_cert],
        'signer_infos': [si],
    })
    return cms.ContentInfo({'content_type': 'signed_data', 'content': signed}).dump(), transaction_id, sender_nonce


def build_getcertinitial(issuer_name, subject_name, signer_key, signer_cert_der,
                         recipient_cert_der, cipher="aes256", digest="sha256",
                         transaction_id=None, sender_nonce=None, sign_key=None):
    """Build a SCEP GetCertInitial (messageType 20) polling message.

    The enveloped payload is an IssuerAndSubject (CA issuer DN + the subject DN
    being polled for) rather than a CSR. 4.4 probe: a party that did NOT originate
    the enrollment asks the server for the issued cert by identity. If the server
    returns it, polling is not bound to the original requester (cert disclosure).

    issuer_name / subject_name are asn1crypto x509.Name objects.
    """
    from asn1crypto.core import Sequence as _Seq

    class IssuerAndSubject(_Seq):
        _fields = [('issuer', x509.Name), ('subject', x509.Name)]

    if sign_key is None:
        sign_key = signer_key
    if sender_nonce is None:
        sender_nonce = os.urandom(16)

    payload = IssuerAndSubject({'issuer': issuer_name, 'subject': subject_name}).dump()
    if transaction_id is None:
        transaction_id = hashlib.sha256(payload).hexdigest()

    envelope = build_enveloped(payload, recipient_cert_der, cipher=cipher)
    signer_cert = x509.Certificate.load(signer_cert_der)
    digest_oid = _DIGEST_OID[digest]
    hfn = _HASHES[digest]()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({'type': 'content_type', 'values': ['data']}),
        cms.CMSAttribute({'type': 'message_digest',
                          'values': [_digest(envelope, digest)]}),
        cms.CMSAttribute({'type': OID_transId,
                          'values': [core.PrintableString(transaction_id)]}),
        cms.CMSAttribute({'type': OID_messageType,
                          'values': [core.PrintableString(MSG_GetCertInitial)]}),
        cms.CMSAttribute({'type': OID_senderNonce,
                          'values': [core.OctetString(sender_nonce)]}),
    ])
    signature = sign_key.sign(signed_attrs.dump(), padding.PKCS1v15(), hfn)

    si = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier('issuer_and_serial_number',
            cms.IssuerAndSerialNumber({'issuer': signer_cert.issuer,
                                       'serial_number': signer_cert.serial_number})),
        'digest_algorithm': {'algorithm': digest_oid},
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': signature,
    })
    signed = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [{'algorithm': digest_oid}],
        'encap_content_info': {'content_type': 'data', 'content': envelope},
        'certificates': [signer_cert],
        'signer_infos': [si],
    })
    pki = cms.ContentInfo({'content_type': 'signed_data', 'content': signed})
    return pki.dump(), transaction_id, sender_nonce


def _digest(data, digest):
    return {'sha1': hashlib.sha1, 'sha256': hashlib.sha256,
            'sha512': hashlib.sha512}[digest](data).digest()


# ---------------------------------------------------------------------------
# CertRep parsing
# ---------------------------------------------------------------------------

def parse_certrep(reply_der, ephemeral_key):
    """Parse a SCEP CertRep. Returns a dict with pkiStatus/failInfo/nonces and,
    on SUCCESS, the issued certificate DER."""
    out = {'pki_status': None, 'pki_status_name': None, 'fail_info': None,
           'fail_info_name': None, 'recipient_nonce': None, 'transaction_id': None,
           'issued_cert_der': None, 'parse_error': None}
    try:
        ci = cms.ContentInfo.load(reply_der)
        signed = ci['content']
        si = signed['signer_infos'][0]
        for attr in si['signed_attrs']:
            oid = attr['type'].dotted
            v = attr['values'][0]
            if oid == OID_pkiStatus:
                s = _read_str(v)
                out['pki_status'] = s
                out['pki_status_name'] = PKISTATUS.get(s, s)
            elif oid == OID_failInfo:
                f = _read_str(v)
                out['fail_info'] = f
                out['fail_info_name'] = FAILINFO.get(f, f)
            elif oid == OID_recipientNonce:
                out['recipient_nonce'] = _read_octets(v).hex()
            elif oid == OID_transId:
                out['transaction_id'] = _read_str(v)

        if out['pki_status'] == '0':  # SUCCESS -> decrypt the enveloped issued cert
            envelope = signed['encap_content_info']['content'].native
            inner = decrypt_enveloped(envelope, ephemeral_key)
            deg = cms.ContentInfo.load(inner)['content']  # degenerate SignedData
            certs = deg['certificates']
            if certs:
                out['issued_cert_der'] = certs[0].chosen.dump()
    except Exception as e:
        out['parse_error'] = "%s: %s" % (type(e).__name__, e)
    return out


def _read_str(any_val):
    raw = any_val.dump()
    try:
        return core.PrintableString.load(raw).native
    except Exception:
        try:
            return core.UTF8String.load(raw).native
        except Exception:
            return any_val.native


def _read_octets(any_val):
    return core.OctetString.load(any_val.dump()).native


def read_pkistatus(reply_der):
    """Extract pkiStatus from a CertRep without needing the decrypt key (it's a
    signed attribute). Returns '0'/'2'/'3' or None if unreadable."""
    try:
        ci = cms.ContentInfo.load(reply_der)
        si = ci['content']['signer_infos'][0]
        for attr in si['signed_attrs']:
            if attr['type'].dotted == OID_pkiStatus:
                return _read_str(attr['values'][0])
    except Exception:
        return None
    return None


def read_failinfo(reply_der):
    """Extract SCEP failInfo (0-4) from a CertRep signed attr, no decrypt needed."""
    try:
        ci = cms.ContentInfo.load(reply_der)
        si = ci['content']['signer_infos'][0]
        for attr in si['signed_attrs']:
            if attr['type'].dotted == OID_failInfo:
                return _read_str(attr['values'][0])
    except Exception:
        return None
    return None


def fuzz_corpus(pki):
    """Given a valid baseline PKIMessage, return an ordered list of (name, bytes)
    malformations targeting the ASN.1/CMS/DER + transport layers. Each is one
    deliberate deviation, to be fired at every server and bucketed by response."""
    import os
    cls_, meth, tag, hdr, content, _ = parser.parse(pki)

    def der_len(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(b)]) + b

    muts = []
    muts.append(("truncate-50pct", pki[:len(pki) // 2]))
    muts.append(("truncate-stub", pki[:8]))
    muts.append(("outer-len-overflow", bytes([pki[0]]) + b'\x84\x7f\xff\xff\xff' + content))
    muts.append(("outer-len-underflow", bytes([pki[0]]) + der_len(16) + content))
    muts.append(("trailing-garbage", pki + b'\xDE\xAD\xBE\xEF' * 64))
    nested = pki
    for _ in range(500):
        nested = b'\xA0' + der_len(len(nested)) + nested
    muts.append(("deep-nest-500", nested))
    muts.append(("indefinite-length", bytes([pki[0]]) + b'\x80' + content + b'\x00\x00'))
    muts.append(("bad-contenttype-oid",
                 pki.replace(b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02',
                             b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x63', 1)))
    mid = len(pki) // 2
    muts.append(("null-injection", pki[:mid] + b'\x00' * 16 + pki[mid:]))
    muts.append(("empty-body", b""))
    muts.append(("random-4k", os.urandom(4096)))
    muts.append(("not-der-http", b"POST / HTTP/1.1\r\nHost: x\r\n\r\n" + b"A" * 128))
    return muts


def fuzz_corpus_deep(pki):
    """Higher-effort crash hunt: extreme nesting (stack exhaustion), integer-overflow
    length fields, intra-CMS/envelope corruption, and allocation stress. These reach
    past the outer wrapper into the parse machinery where bounds bugs live."""
    import os
    cls_, meth, tag, hdr, content, _ = parser.parse(pki)

    def der_len(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(b)]) + b

    muts = []
    nested = pki
    for _ in range(50000):
        nested = b'\xA0' + der_len(len(nested)) + nested
    muts.append(("deep-nest-50k", nested))
    muts.append(("intlen-4gib", bytes([pki[0]]) + b'\x84\xff\xff\xff\xff' + content[:32]))
    muts.append(("intlen-8byte",
                 bytes([pki[0]]) + b'\x88\xff\xff\xff\xff\xff\xff\xff\xff' + content[:32]))
    env_start = pki.find(b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01')
    if env_start > 0:
        b = bytearray(pki)
        for i in range(max(0, len(b) - 40), len(b) - 8):
            b[i] ^= 0xFF
        muts.append(("envelope-ct-bitflip", bytes(b)))
        muts.append(("truncate-at-envelope", pki[:env_start + 20]))
    giant = b'\x04\x84\x00\x10\x00\x00' + b'A' * 0x100000
    muts.append(("giant-octetstring-1mb", pki[:len(hdr)] + giant + content))
    return muts


# ---------------------------------------------------------------------------
# Recipient selection (which cert from a getca bundle to envelope to)
# ---------------------------------------------------------------------------

def pick_recipient(cert_ders):
    """Choose the encryption recipient from a getca bundle.
    Prefer an RA key-encipherment cert (NDES split); else RA-dual; else the CA."""
    ca = None
    ra_dual = None
    for der in cert_ders:
        c = c_x509.load_der_x509_certificate(der)
        try:
            bc = c.extensions.get_extension_for_class(c_x509.BasicConstraints).value
            if bc.ca:
                ca = der
                continue
        except c_x509.ExtensionNotFound:
            pass
        try:
            ku = c.extensions.get_extension_for_class(c_x509.KeyUsage).value
            if ku.key_encipherment and not ku.digital_signature:
                return der, "RA-encryption"
            if ku.key_encipherment and ku.digital_signature:
                ra_dual = der
        except c_x509.ExtensionNotFound:
            ra_dual = ra_dual or der
    if ra_dual:
        return ra_dual, "RA-dual"
    return ca, "CA-signing"
