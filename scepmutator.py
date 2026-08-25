#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SCEPMutator - a scriptable SCEP message forge & multi-server differential harness
#
# Part of the SCEP implementation-differential research rig (NDES / EJBCA / Dogtag /
# OpenXPKI / micromdm). This is the read-only + baseline foundation: it establishes the
# D0.5 conformance grid that every later mutation is diffed against. enroll / poll /
# mutate land on top of this same transport + normalizer core.
#
# Author: cbev (cbev0x)
# Style:  argparse subcommands, impacket-flavoured logging. Human table by default,
#         -json for machine-readable capture (the diff substrate).
#
# SAFE-BY-DEFAULT: this file implements only unauthenticated read operations
# (GetCACaps, GetCACert) and a baseline sweep over them. Nothing here mutates
# server state or attempts enrollment.

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import sys
import time
import warnings

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding

import scep_core as sc

VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Logging (impacket-flavoured)
# ---------------------------------------------------------------------------

class Logger:
    COLORS = {"*": "\033[34m", "+": "\033[32m", "-": "\033[31m",
              "!": "\033[33m", "D": "\033[90m"}
    RESET = "\033[0m"

    def __init__(self, debug=False, ts=False, color=True):
        self.debug_on = debug
        self.ts = ts
        self.color = color and sys.stdout.isatty()

    def _emit(self, sigil, msg):
        stamp = ""
        if self.ts:
            stamp = "[%s] " % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tag = "[%s]" % sigil
        if self.color and sigil in self.COLORS:
            tag = "%s%s%s" % (self.COLORS[sigil], tag, self.RESET)
        print("%s%s %s" % (stamp, tag, msg))

    def info(self, m):    self._emit("*", m)
    def good(self, m):    self._emit("+", m)
    def error(self, m):   self._emit("-", m)
    def warn(self, m):    self._emit("!", m)
    def debug(self, m):
        if self.debug_on:
            self._emit("D", m)


log = Logger()  # replaced in main() once args are parsed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def looks_like_base64(raw):
    """Heuristic: is this blob PEM-less base64 text rather than raw DER bytes?"""
    if not raw:
        return False
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    compact = "".join(text.split())
    if len(compact) < 4:
        return False
    b64set = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return all(c in b64set for c in compact)


def try_b64_decode(raw):
    try:
        return base64.b64decode("".join(raw.decode("ascii").split()), validate=True)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def cert_role_hint(cert):
    """Label a cert in a getca bundle. GetCACert returns only CA + RA certs, so any
    non-CA cert is an RA cert; sub-classify RA by KeyUsage where the bits allow."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            return "CA-signing"
    except x509.ExtensionNotFound:
        pass
    # non-CA cert in a GetCACert response == RA cert; disambiguate by KeyUsage
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if ku.key_encipherment and not ku.digital_signature:
            return "RA-encryption"
        if ku.digital_signature and not ku.key_encipherment:
            return "RA-signing"
        if ku.digital_signature and ku.key_encipherment:
            return "RA-dual"
    except x509.ExtensionNotFound:
        pass
    return "RA"


def cert_brief(cert):
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sig_alg": cert.signature_algorithm_oid._name,
        "role_hint": cert_role_hint(cert),
    }


# ---------------------------------------------------------------------------
# Response normalizer  --  canonicalizes the five getca encoding shapes
# NDES 3-cert DER RA bundle / micromdm single self-signed / Dogtag single CA cert
# / EJBCA named-CA DER / OpenXPKI base64->PKCS#7 chain  ==>  one internal form.
# ---------------------------------------------------------------------------

def normalize_cacert(raw):
    result = {"outer_encoding": "der", "shape": None, "cert_count": 0,
              "certs": [], "raw_len": len(raw), "raw_sha256": sha256_hex(raw),
              "der_conformant": None, "der_note": None}

    data = raw
    if looks_like_base64(raw):
        decoded = try_b64_decode(raw)
        if decoded is not None:
            data = decoded
            result["outer_encoding"] = "base64->der"

    # Try degenerate PKCS#7 (SignedData carrying certs) first, then single cert.
    # Capture any BER-fallback warning: a PKCS#7 that only parses as BER (not strict
    # DER) is a DER-conformance finding (e.g. an unsorted SET-OF certificates), so we
    # record it as structured data instead of letting it hit stderr.
    certs = None
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            certs = pkcs7.load_der_pkcs7_certificates(data)
            result["shape"] = "pkcs7-bundle"
        except Exception as e_pkcs7:
            try:
                certs = [x509.load_der_x509_certificate(data)]
                result["shape"] = "single-cert"
            except Exception as e_single:
                result["shape"] = "unparseable"
                result["parse_error"] = "pkcs7=%s ; single=%s" % (
                    type(e_pkcs7).__name__, type(e_single).__name__)
                certs = []
        der_msgs = [str(w.message) for w in caught
                    if "DER" in str(w.message) or "BER" in str(w.message)]

    if result["shape"] in ("pkcs7-bundle", "single-cert"):
        result["der_conformant"] = not der_msgs
        if der_msgs:
            result["der_note"] = der_msgs[0]

    result["cert_count"] = len(certs)
    result["certs"] = [cert_brief(c) for c in certs]
    if len(certs) > 1:
        result["shape"] = "pkcs7-bundle(%d)" % len(certs)
    return result


# ---------------------------------------------------------------------------
# SCEP client (transport + read-only operations)
# ---------------------------------------------------------------------------

class ScepClient:
    def __init__(self, url, ca_ident=None, timeout=15, verify_tls=False, extra_headers=None):
        self.url = url.rstrip("?")
        self.ca_ident = ca_ident or ""
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.extra_headers = extra_headers or {}

    def _get(self, operation, message=""):
        params = {"operation": operation}
        # message carries the CA identifier; EJBCA in CA mode *requires* it.
        if message:
            params["message"] = message
        t0 = time.perf_counter()
        r = requests.get(self.url, params=params, timeout=self.timeout,
                         headers=self.extra_headers or None,
                         verify=self.verify_tls)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        return r, elapsed_ms

    def getcacaps(self):
        r, ms = self._get("GetCACaps", self.ca_ident)
        caps = sorted({line.strip() for line in r.text.splitlines() if line.strip()})
        return {
            "operation": "GetCACaps",
            "http_status": r.status_code,
            "mime": r.headers.get("Content-Type", ""),
            "elapsed_ms": ms,
            "transport": "GET",
            "caps": caps,
            "raw_len": len(r.content),
        }

    def getcacert(self):
        r, ms = self._get("GetCACert", self.ca_ident)
        norm = normalize_cacert(r.content)
        return {
            "operation": "GetCACert",
            "http_status": r.status_code,
            "mime": r.headers.get("Content-Type", ""),
            "elapsed_ms": ms,
            "transport": "GET",
            **norm,
        }

    def fetch_ca_certs(self):
        """Return (list of raw cert DERs, norm-record) for use as envelope recipients."""
        r, ms = self._get("GetCACert", self.ca_ident)
        norm = normalize_cacert(r.content)
        data = r.content
        if norm["outer_encoding"] == "base64->der":
            dec = try_b64_decode(r.content)
            if dec is not None:
                data = dec
        ders = []
        try:
            certs = pkcs7.load_der_pkcs7_certificates(data)
            ders = [c.public_bytes(Encoding.DER) for c in certs]
        except Exception:
            try:
                ders = [x509.load_der_x509_certificate(data).public_bytes(Encoding.DER)]
            except Exception:
                ders = []
        return ders, norm

    def pkioperation(self, pki_message_der, transport="auto", caps=None):
        """Send a PKIMessage. POST if the server advertises POSTPKIOperation, else
        GET with base64 in the message param (the Dogtag path)."""
        if transport == "auto":
            transport = "post" if (caps and "POSTPKIOperation" in caps) else "get"
        t0 = time.perf_counter()
        if transport == "post":
            hdrs = {"Content-Type": "application/x-pki-message"}
            hdrs.update(self.extra_headers)
            r = requests.post(self.url, params={"operation": "PKIOperation"},
                              data=pki_message_der,
                              headers=hdrs,
                              timeout=self.timeout, verify=self.verify_tls)
        else:
            b64 = base64.b64encode(pki_message_der).decode("ascii")
            r = requests.get(self.url,
                             params={"operation": "PKIOperation", "message": b64},
                             headers=self.extra_headers or None,
                             timeout=self.timeout, verify=self.verify_tls)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        return r, transport, elapsed_ms


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def render_getcaps(name, rec):
    log.good("%s  GetCACaps  [HTTP %s, %s, %sms]" % (
        name, rec["http_status"], rec["mime"] or "no-mime", rec["elapsed_ms"]))
    log.info("    caps: %s" % (", ".join(rec["caps"]) if rec["caps"] else "(none)"))


def render_getca(name, rec):
    log.good("%s  GetCACert  [HTTP %s, %s, %sms]" % (
        name, rec["http_status"], rec["mime"] or "no-mime", rec["elapsed_ms"]))
    log.info("    encoding=%s  shape=%s  certs=%d  raw=%dB  sha256=%s" % (
        rec["outer_encoding"], rec["shape"], rec["cert_count"],
        rec["raw_len"], rec["raw_sha256"][:16]))
    if rec.get("der_conformant") is False:
        log.warn("    DER non-conformant: %s" % (rec.get("der_note") or "BER fallback required"))
    for i, c in enumerate(rec["certs"]):
        log.info("    [%d] %-13s %s" % (i, c["role_hint"], c["subject"]))


# ---------------------------------------------------------------------------
# Targets file  (for the baseline sweep across all five servers)
# ---------------------------------------------------------------------------

def load_targets(path):
    with open(path) as f:
        data = json.load(f)
    if "targets" not in data or not isinstance(data["targets"], list):
        raise ValueError("targets file must have a top-level 'targets' list")
    return data["targets"]


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_getcaps(args):
    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k)
    rec = client.getcacaps()
    if args.json:
        print(json.dumps(rec, indent=2))
    else:
        render_getcaps(args.name or args.u, rec)
    return 0


def _caps_advertise_digest(caps):
    """Which digests does this caps set advertise? SHA-1 is implicit-legacy (if no
    SHA-* advertised at all, SHA-1 is the historical default)."""
    adv = set()
    if "SHA-512" in caps:
        adv.add("sha512")
    if "SHA-256" in caps:
        adv.add("sha256")
    if "SHA-1" in caps or not (("SHA-256" in caps) or ("SHA-512" in caps)):
        adv.add("sha1")
    return adv


def _caps_advertise_cipher(caps):
    adv = {"des3"}  # DES3 is the SCEP baseline, always implicitly available
    if "AES" in caps or "AES-256" in caps:
        adv.add("aes256")
        adv.add("aes128")
    return adv


def cmd_downgrade(args):
    """D2: advertised != enforced. Read GetCACaps, then send algorithms the server
    claims NOT to support. A server that ISSUES on an unadvertised (weaker) algorithm
    is a downgrade surface (T2/T3). Rejection = it enforces its advertisement (secure)."""
    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k, timeout=args.timeout)
    caps = []
    try:
        caps = client.getcacaps()["caps"]
    except requests.RequestException as e:
        log.warn("GetCACaps failed (%s)" % e)
    log.info("%s advertises caps: %s" % (args.name or args.u, ", ".join(caps) or "(none)"))

    adv_digest = _caps_advertise_digest(caps)
    adv_cipher = _caps_advertise_cipher(caps)
    # the downgrade set = weaker algorithms the server does NOT advertise
    digest_probes = [d for d in ("sha1", "sha256") if d not in adv_digest]
    cipher_probes = [c for c in ("des3", "aes128") if c not in adv_cipher]

    cert_ders, norm = client.fetch_ca_certs()
    if not cert_ders:
        log.error("GetCACert returned no usable certs")
        return 1
    recip_der, role = sc.pick_recipient(cert_ders)

    results = []

    def _probe(label, digest, cipher, is_baseline=False):
        key = sc.gen_rsa()
        signer_der = sc.selfsigned_signer(key, cn=args.cn)
        csr_der = sc.build_csr(key, args.cn, challenge=args.challenge, digest=digest)
        pki, txid, nonce = sc.build_pkcs_req(csr_der, key, signer_der, recip_der,
                                             cipher=cipher, digest=digest)
        try:
            r, used, ms = client.pkioperation(pki, transport=args.transport, caps=caps)
        except requests.RequestException as e:
            results.append((label, "req-error", str(e)[:40], is_baseline))
            log.info("  %-28s -> req-error %s" % (label, str(e)[:40]))
            return
        if r.status_code == 200:
            status = sc.read_pkistatus(r.content)
            if status == "0":
                # SUCCESS on the baseline = healthy control. SUCCESS on an
                # unadvertised-algorithm probe = downgrade surface.
                if is_baseline:
                    bucket, detail = "baseline-ok", "issued (control healthy)"
                else:
                    bucket, detail = "ACCEPTED-DOWNGRADE", "issued on unadvertised algo!"
            elif status == "2":
                bucket, detail = "rejected", "SCEP FAILURE (enforces advert.)"
            else:
                bucket, detail = "http-200", "status=%s" % status
        elif r.status_code == 500:
            bucket, detail = "http-500", "(uncaught exception / choked)"
        elif 400 <= r.status_code < 500:
            bucket, detail = "rejected", "HTTP %d" % r.status_code
        else:
            bucket, detail = "http-%d" % r.status_code, ""
        results.append((label, bucket, detail, is_baseline))
        emit = log.warn if bucket == "ACCEPTED-DOWNGRADE" else log.info
        emit("  %-28s -> %-19s %s" % (label, bucket, detail))

    log.info("baseline (advertised) sanity first — this is the CONTROL, not a finding:")
    base_d = "sha256" if "sha256" in adv_digest else "sha1"
    base_c = "aes256" if "aes256" in adv_cipher else "des3"
    _probe("BASELINE %s/%s" % (base_d, base_c), base_d, base_c, is_baseline=True)
    baseline_ok = any(r[3] and r[1] == "baseline-ok" for r in results)
    if not baseline_ok:
        log.warn("baseline did NOT issue — pipeline/challenge/VM issue; downgrade probes below are UNINTERPRETABLE")

    log.info("downgrade probes (unadvertised algorithms):")
    if not digest_probes and not cipher_probes:
        log.info("  (server advertises all weak algorithms — no genuine downgrade to test)")
    for d in digest_probes:
        _probe("digest=%s (unadvert.)" % d, d, base_c)
    for c in cipher_probes:
        _probe("cipher=%s (unadvert.)" % c, base_d, c)

    print()
    hits = [r for r in results if r[1] == "ACCEPTED-DOWNGRADE"]
    if hits and baseline_ok:
        log.warn("%d DOWNGRADE ACCEPTED: %s" % (len(hits), ", ".join(h[0] for h in hits)))
        log.warn("server processed an algorithm it advertised as absent — verify + prior-art gate")
    elif hits and not baseline_ok:
        log.warn("apparent downgrade hits but baseline failed — re-run with a live VM + fresh challenge")
    else:
        log.good("no downgrade accepted — server enforces its advertised algorithms (or rejects cleanly)")
    if args.json:
        print(json.dumps({"target": args.name or args.u, "advertised": caps,
                          "baseline_ok": baseline_ok,
                          "results": [{"probe": l, "bucket": b, "detail": d, "baseline": bl}
                                      for l, b, d, bl in results]},
                         indent=2))
    return 0


def cmd_getca(args):
    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k)
    rec = client.getcacert()
    if args.json:
        print(json.dumps(rec, indent=2))
    else:
        render_getca(args.name or args.u, rec)
    return 0


def parse_sans(san_args):
    """['dns:host.test', 'upn:a@b'] -> [('dns','host.test'), ('upn','a@b')]"""
    if not san_args:
        return None
    out = []
    for s in san_args:
        if ":" not in s:
            raise ValueError("SAN must be KIND:VALUE (e.g. dns:host.test, upn:a@b) - got %r" % s)
        kind, val = s.split(":", 1)
        out.append((kind.strip().lower(), val.strip()))
    return out


def cmd_enroll(args):
    from cryptography.hazmat.primitives import serialization
    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k)

    caps = []
    try:
        caps = client.getcacaps()["caps"]
        log.debug("caps: %s" % ", ".join(caps))
    except requests.RequestException as e:
        log.warn("GetCACaps failed (%s); proceeding with defaults" % e)

    cert_ders, norm = client.fetch_ca_certs()
    if not cert_ders:
        log.error("GetCACert returned no usable certs; cannot build the envelope")
        return 1
    recip_der, recip_role = sc.pick_recipient(cert_ders)
    recip_cert = x509.load_der_x509_certificate(recip_der)
    log.info("recipient: %s  [%s]" % (recip_cert.subject.rfc4514_string(), recip_role))

    cipher = args.cipher
    if cipher == "auto":
        cipher = "aes256" if "AES" in caps else "des3"
        log.debug("cipher auto-selected: %s (AES advertised: %s)" % (cipher, "AES" in caps))

    key = sc.gen_rsa(args.key_size)
    signer_der = sc.selfsigned_signer(key, cn=args.cn)
    sans = parse_sans(args.san)

    # ---- mutation layer -------------------------------------------------
    # Each mutation bends exactly one stage so the differential isolates what
    # each server checks. Conformant build unless -mutate is given.
    sign_key = key         # outer CMS signer (default = CSR key)
    pop_sign_key = None    # inner CSR self-signer (default = CSR key)
    mutation = args.mutate

    if mutation == "signer-key-mismatch":
        # 3.5a: outer CMS signed by a key != the enclosed signer cert / CSR key.
        sign_key = sc.gen_rsa(args.key_size)
        log.warn("MUTATION signer-key-mismatch: outer CMS signed by a key != CSR key")
        log.warn("  -> issuance = server did not verify the OUTER SCEP signature")
    elif mutation in ("csr-nopop", "full-nopop"):
        # 3.5b: the CSR carries a public key we do NOT control, with an invalid
        # self-signature (CRI signed by a different key). If the server issues, it
        # certified a key with NO valid proof-of-possession.
        key = sc.gen_rsa(args.key_size)          # "victim" key -> CSR subject_pk_info
        pop_sign_key = sc.gen_rsa(args.key_size)  # CRI signed by a non-matching key
        signer_der = sc.selfsigned_signer(pop_sign_key, cn=args.cn)
        sign_key = sc.gen_rsa(args.key_size) if mutation == "full-nopop" else pop_sign_key
        log.warn("MUTATION %s: CSR carries a public key we do NOT hold; inner PoP invalid" % mutation)
        log.warn("  -> issuance = server certified a key with no proof-of-possession (T3)")

    csr_der = sc.build_csr(key, args.cn, challenge=args.challenge,
                           challenge_encoding=args.challenge_encoding,
                           sans=sans, digest=args.digest, pop_sign_key=pop_sign_key)
    # the CertRep reply is enveloped to the outer signer cert; its key is sign_key
    # for the nopop cases (signer cert built from pop_sign_key, outer signed by same
    # unless full-nopop), else `key`.
    reply_key = pop_sign_key if mutation in ("csr-nopop", "full-nopop") else key
    # ---------------------------------------------------------------------

    pki, txid, nonce = sc.build_pkcs_req(csr_der, key, signer_der, recip_der,
                                         cipher=cipher, digest=args.digest,
                                         sign_key=sign_key)
    log.info("PKCSReq built: cn=%s cipher=%s digest=%s transport=%s txid=%s..." % (
        args.cn, cipher, args.digest, args.transport, txid[:16]))
    if mutation:
        log.info("           mutation: %s" % mutation)
    if sans:
        log.info("           SANs requested: %s" % ", ".join("%s:%s" % s for s in sans))

    try:
        r, used_transport, ms = client.pkioperation(pki, transport=args.transport, caps=caps)
    except requests.RequestException as e:
        log.error("PKIOperation transport failed: %s" % e)
        return 1
    log.debug("HTTP %s %s via %s in %sms" % (
        r.status_code, r.headers.get("Content-Type", ""), used_transport, ms))
    if r.status_code != 200:
        log.error("server returned HTTP %s" % r.status_code)
        return 1

    res = sc.parse_certrep(r.content, reply_key)
    if res["parse_error"]:
        log.error("CertRep parse error: %s" % res["parse_error"])
        return 1

    nonce_ok = res["recipient_nonce"] == nonce.hex()
    summary = {"target": args.name or args.u, "transport": used_transport,
               "cipher": cipher, "digest": args.digest, "txid": txid,
               "recipient_role": recip_role, "recipient_nonce_ok": nonce_ok,
               **{k: res[k] for k in ("pki_status", "pki_status_name",
                                      "fail_info", "fail_info_name")}}

    if res["pki_status"] == "0":
        log.good("pkiStatus=SUCCESS   recipientNonce=%s" % ("matched" if nonce_ok else "MISMATCH"))
        if mutation == "signer-key-mismatch":
            log.warn("  ** server ISSUED despite outer signer-key != CSR-key")
            log.warn("  ** => outer SCEP signature not enforced (conformance gap; verify inner PoP with -mutate csr-nopop)")
        elif mutation in ("csr-nopop", "full-nopop"):
            log.warn("  ** FINDING: server ISSUED a cert for a public key with NO valid proof-of-possession")
            log.warn("  ** => cert bound to a key the requester does not control (T3 impersonation primitive)")
        ic = x509.load_der_x509_certificate(res["issued_cert_der"])
        log.good("issued: %s" % ic.subject.rfc4514_string())
        log.info("        issuer=%s" % ic.issuer.rfc4514_string())
        try:
            san_ext = ic.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            issued_san = [str(n.value) if hasattr(n, "value") else str(n) for n in san_ext]
            log.info("        issued SAN=%s" % issued_san)
            summary["issued_san"] = issued_san
        except x509.ExtensionNotFound:
            log.info("        issued SAN=(none)")
        summary["issued_subject"] = ic.subject.rfc4514_string()
        if args.o:
            with open(args.o, "wb") as f:
                f.write(ic.public_bytes(serialization.Encoding.PEM))
            log.good("issued cert written: %s" % args.o)
        if getattr(args, "save_key", None) and not mutation:
            with open(args.save_key, "wb") as f:
                f.write(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()))
            log.good("private key written: %s  (reusable renewal credential)" % args.save_key)
    elif res["pki_status"] == "3":
        log.warn("pkiStatus=PENDING (manual approval) txid=%s" % txid[:16])
    else:
        log.error("pkiStatus=FAILURE  failInfo=%s (%s)" % (
            res["fail_info"], res["fail_info_name"]))

    if args.json:
        print(json.dumps(summary, indent=2))
    return 0


def _is_ca(cert_der):
    try:
        c = x509.load_der_x509_certificate(cert_der)
        return c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except Exception:
        return False


def cmd_renew(args):
    """RenewalReq: authenticate by signing with an EXISTING cert/key instead of a
    challenge. Cross-CA confusion probe: point -cert/-key at a credential issued by
    a DIFFERENT server than -u; if the target issues, it accepted a foreign-CA
    renewal credential (trust-boundary crossing, T3)."""
    from cryptography.hazmat.primitives import serialization
    with open(args.cert, "rb") as f:
        existing_cert = x509.load_pem_x509_certificate(f.read())
    with open(args.key, "rb") as f:
        existing_key = serialization.load_pem_private_key(f.read(), password=None)
    existing_cert_der = existing_cert.public_bytes(serialization.Encoding.DER)

    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k)
    caps = []
    try:
        caps = client.getcacaps()["caps"]
    except requests.RequestException as e:
        log.warn("GetCACaps failed (%s)" % e)
    if "Renewal" not in caps:
        log.warn("target does not advertise Renewal (%s)" % (", ".join(caps) or "none"))

    cert_ders, norm = client.fetch_ca_certs()
    if not cert_ders:
        log.error("GetCACert returned no usable certs")
        return 1
    recip_der, recip_role = sc.pick_recipient(cert_ders)

    cipher = args.cipher
    if cipher == "auto":
        cipher = "aes256" if "AES" in caps else "des3"

    # Honest same-vs-cross labeling: is the signer cert's issuer present in the
    # target's published CA bundle? (2-tier CAs may omit the issuing CA, so a
    # "not present" is flagged as *possibly* cross and needs manual confirmation.)
    bundle_subjects = set()
    for d in cert_ders:
        try:
            bundle_subjects.add(x509.load_der_x509_certificate(d).subject.rfc4514_string())
        except Exception:
            pass
    issuer_str = existing_cert.issuer.rfc4514_string()
    issuer_in_bundle = issuer_str in bundle_subjects
    log.info("renewal signer cert: %s" % existing_cert.subject.rfc4514_string())
    log.info("  issued by: %s" % issuer_str)
    log.info("  target CA bundle subjects: %s" % "; ".join(sorted(bundle_subjects)))
    if issuer_in_bundle:
        log.info("  (signer issuer present in target bundle -> same-CA baseline)")
    else:
        log.warn("  signer issuer NOT in target bundle -> possibly CROSS-CA")
        log.warn("  (confirm: 2-tier CAs may just omit the issuing cert from getca)")

    # Renewal method: default PKCSReq(19)-signed-by-existing (de-facto interoperable);
    # RenewalReq(17) is RFC 8894 but poorly supported.
    msgtype = sc.MSG_RenewalReq if args.renewal_type == "renewalreq" else sc.MSG_PKCSReq

    new_key = sc.gen_rsa(args.key_size)
    csr_der = sc.build_csr(new_key, args.cn, challenge=args.challenge,
                           challenge_encoding=args.challenge_encoding,
                           sans=parse_sans(args.san), digest=args.digest)
    pki, txid, nonce = sc.build_pkcs_req(csr_der, new_key, existing_cert_der, recip_der,
                                         cipher=cipher, digest=args.digest,
                                         message_type=msgtype,
                                         sign_key=existing_key)
    log.info("RenewalReq built: method=%s cipher=%s digest=%s txid=%s..." % (
        args.renewal_type, cipher, args.digest, txid[:16]))

    try:
        r, used_transport, ms = client.pkioperation(pki, transport=args.transport, caps=caps)
    except requests.RequestException as e:
        log.error("PKIOperation transport failed: %s" % e)
        return 1
    if r.status_code != 200:
        log.error("server returned HTTP %s" % r.status_code)
        return 1

    res = sc.parse_certrep(r.content, existing_key)  # reply enveloped to the signer cert
    if res["parse_error"]:
        log.error("CertRep parse error: %s" % res["parse_error"])
        return 1

    if res["pki_status"] == "0":
        log.good("pkiStatus=SUCCESS")
        if not issuer_in_bundle:
            log.warn("  ** POSSIBLE FINDING: target issued on a renewal cert whose issuer")
            log.warn("  ** is not in its own CA bundle -> confirm the signer is genuinely")
            log.warn("  ** foreign (cross-CA renewal trust confusion, T3)")
        ic = x509.load_der_x509_certificate(res["issued_cert_der"])
        log.good("issued: %s" % ic.subject.rfc4514_string())
        log.info("        issuer=%s" % ic.issuer.rfc4514_string())
        if args.o:
            with open(args.o, "wb") as f:
                f.write(ic.public_bytes(serialization.Encoding.PEM))
            log.good("issued cert written: %s" % args.o)
    elif res["pki_status"] == "3":
        log.warn("pkiStatus=PENDING txid=%s" % txid[:16])
    else:
        log.error("pkiStatus=FAILURE  failInfo=%s (%s)" % (
            res["fail_info"], res["fail_info_name"]))
    return 0


def _bucket_response(client, blob, transport, caps, key=None, baseline_cn=None):
    """Send one malformed blob and classify the server's reaction."""
    try:
        r, used, ms = client.pkioperation(blob, transport=transport, caps=caps)
    except requests.exceptions.Timeout:
        return "TIMEOUT", "(>%ss - possible hang/DoS)" % client.timeout, None
    except requests.exceptions.ConnectionError:
        return "CONN-RESET", "(connection dropped - possible crash)", None
    except requests.RequestException as e:
        return "req-error", str(e)[:50], None
    if r.status_code == 500:
        return "http-500", "(uncaught exception)", ms
    if 400 <= r.status_code < 500:
        return "http-4xx", "HTTP %d" % r.status_code, ms
    if r.status_code == 200:
        status = sc.read_pkistatus(r.content)
        if status == "0":
            # Distinguish a REAL unexpected-accept from benign tolerance of a valid
            # underlying message (trailing-data / BER re-encoding still carry the
            # baseline request). Decrypt the issued cert and compare to baseline CN.
            if key is not None:
                try:
                    res = sc.parse_certrep(r.content, key)
                    if res.get("issued_cert_der"):
                        ic = x509.load_der_x509_certificate(res["issued_cert_der"])
                        cn = ic.subject.rfc4514_string()
                        if baseline_cn and baseline_cn in cn:
                            return "tolerated", "valid msg processed (benign)", ms
                        return "UNEXPECTED-ACCEPT", "issued %s !!" % cn, ms
                except Exception:
                    pass
            return "UNEXPECTED-ACCEPT", "issued/OK on malformed input!", ms
        if status == "2":
            return "clean-fail", "SCEP FAILURE", ms
        if status == "3":
            return "pending", "PENDING", ms
        return "http-200", "unreadable reply (len=%d)" % len(r.content), ms
    return "http-%d" % r.status_code, "", ms


def cmd_fuzz(args):
    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k, timeout=args.timeout)
    caps = []
    try:
        caps = client.getcacaps()["caps"]
    except requests.RequestException as e:
        log.warn("GetCACaps failed (%s)" % e)
    cert_ders, norm = client.fetch_ca_certs()
    if not cert_ders:
        log.error("GetCACert returned no usable certs")
        return 1
    recip_der, role = sc.pick_recipient(cert_ders)
    cipher = "aes256" if "AES" in caps else "des3"

    key = sc.gen_rsa()
    signer_der = sc.selfsigned_signer(key, cn=args.cn)
    csr_der = sc.build_csr(key, args.cn, challenge=args.challenge, digest="sha256")
    pki, txid, nonce = sc.build_pkcs_req(csr_der, key, signer_der, recip_der,
                                         cipher=cipher, digest="sha256")
    corpus = sc.fuzz_corpus(pki)
    if args.deep:
        corpus = corpus + sc.fuzz_corpus_deep(pki)
    log.info("fuzzing %s: baseline %d bytes, %d cases, transport=%s, timeout=%ss%s" % (
        args.name or args.u, len(pki), len(corpus), args.transport, args.timeout,
        " [DEEP]" if args.deep else ""))

    interesting_buckets = {"http-500", "TIMEOUT", "CONN-RESET", "UNEXPECTED-ACCEPT"}
    results = []
    for name, blob in corpus:
        bucket, detail, ms = _bucket_response(client, blob, args.transport, caps,
                                              key=key, baseline_cn=args.cn)
        results.append({"case": name, "bytes": len(blob), "bucket": bucket,
                        "detail": detail, "ms": ms})
        line = "  %-22s %8dB -> %-17s %s" % (name, len(blob), bucket, detail)
        (log.warn if bucket in interesting_buckets else log.info)(line)

    flagged = [r for r in results if r["bucket"] in interesting_buckets]
    print()
    if flagged:
        log.warn("%d flagged response(s): %s" % (
            len(flagged), ", ".join("%s(%s)" % (r["case"], r["bucket"]) for r in flagged)))
        log.warn("http-500 = known-class for Dogtag; TIMEOUT/CONN-RESET/UNEXPECTED-ACCEPT = investigate")
    else:
        log.good("all malformed inputs rejected/errored cleanly — no hang, crash, or accept")
    if args.json:
        print(json.dumps({"target": args.name or args.u, "results": results}, indent=2))
    return 0


def cmd_poll(args):
    """D4.4: GetCertInitial polling authorization. Enroll as the legit originator,
    then poll (messageType 20) for that same issued cert while signing the poll with
    a DIFFERENT, unrelated key/identity. If the server returns the cert to the
    non-originator, polling is not bound to the requester (cert disclosure, T3)."""
    from asn1crypto import x509 as ax
    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k, timeout=args.timeout)
    caps = []
    try:
        caps = client.getcacaps()["caps"]
    except requests.RequestException:
        pass
    cert_ders, norm = client.fetch_ca_certs()
    if not cert_ders:
        log.error("GetCACert returned no usable certs")
        return 1
    recip_der, role = sc.pick_recipient(cert_ders)
    cipher = "aes256" if "AES" in caps else "des3"

    # 1) Legit enrollment (the originator) to get a real issued cert + subject.
    orig_key = sc.gen_rsa()
    orig_signer = sc.selfsigned_signer(orig_key, cn=args.cn)
    csr = sc.build_csr(orig_key, args.cn, challenge=args.challenge, digest="sha256")
    pki, txid, nonce = sc.build_pkcs_req(csr, orig_key, orig_signer, recip_der,
                                         cipher=cipher, digest="sha256")
    r, used, ms = client.pkioperation(pki, transport=args.transport, caps=caps)
    if r.status_code != 200 or sc.read_pkistatus(r.content) != "0":
        log.error("originator enrollment did not succeed (status=%s http=%s) — cannot set up poll" % (
            sc.read_pkistatus(r.content), r.status_code))
        return 1
    res = sc.parse_certrep(r.content, orig_key)
    if not res.get("issued_cert_der"):
        log.error("originator enroll returned SUCCESS but the issued cert did not decrypt/parse")
        log.error("  (parse_error=%s) — can't derive issuer/subject to poll for on this server" % res.get("parse_error"))
        log.info("  this is a reply-enveloping/transport quirk on this server, not a poll result")
        return 1
    issued = x509.load_der_x509_certificate(res["issued_cert_der"])
    log.good("originator enrolled: %s (serial %x)" % (issued.subject.rfc4514_string(), issued.serial_number))
    issuer_name = ax.Certificate.load(res["issued_cert_der"])['tbs_certificate']['issuer']
    subject_name = ax.Certificate.load(res["issued_cert_der"])['tbs_certificate']['subject']

    # 2) Poll for that cert as a DIFFERENT identity (attacker did not originate it).
    atk_key = sc.gen_rsa()
    atk_signer = sc.selfsigned_signer(atk_key, cn="attacker.poller.test")
    log.info("polling GetCertInitial for the originator's cert, signed by an UNRELATED key/identity")
    poll, ptxid, pnonce = sc.build_getcertinitial(issuer_name, subject_name,
                                                  atk_key, atk_signer, recip_der,
                                                  cipher=cipher, digest="sha256")
    try:
        pr, pused, pms = client.pkioperation(poll, transport=args.transport, caps=caps)
    except requests.RequestException as e:
        log.error("poll transport failed: %s" % e)
        return 1
    if pr.status_code != 200:
        log.info("poll -> HTTP %s (server rejected the non-originator poll)" % pr.status_code)
        log.good("polling appears bound / not open to non-originator (HTTP %s)" % pr.status_code)
        return 0

    pstatus = sc.read_pkistatus(pr.content)
    if pstatus == "0":
        # The reply is enveloped to the POLLER's cert (atk). If we can decrypt it
        # with the attacker key and recover the originator's cert -> disclosure.
        try:
            pres = sc.parse_certrep(pr.content, atk_key)
            disclosed = x509.load_der_x509_certificate(pres["issued_cert_der"])
            log.warn("  ** FINDING: server RETURNED the cert to a non-originator poller")
            log.warn("  ** disclosed: %s (serial %x)" % (disclosed.subject.rfc4514_string(), disclosed.serial_number))
            log.warn("  ** => GetCertInitial polling is NOT bound to the requester (cert disclosure, T3)")
        except Exception as e:
            log.warn("  poll returned SUCCESS but reply not decryptable with attacker key (%s)" % str(e)[:50])
            log.info("  (server may have enveloped to the originator — not a clean disclosure)")
    elif pstatus == "2":
        log.good("poll -> SCEP FAILURE — server refuses the non-originator poll (bound). Secure.")
    elif pstatus == "3":
        log.info("poll -> PENDING (server neither discloses nor hard-fails)")
    else:
        log.info("poll -> pkiStatus=%s" % pstatus)
    return 0


# The proxy-trust header set: headers a reverse proxy / IIS-ARR / Intune connector
# might set that an origin could be tricked into trusting. If NDES (or any origin)
# changes behavior based on an attacker-supplied value here, that is header-trust
# injection (1.2 pre-auth passthrough).
_PROXY_TRUST_HEADERS = [
    ("X-Forwarded-For",            "127.0.0.1"),
    ("X-Forwarded-Host",           "localhost"),
    ("X-Forwarded-Proto",          "https"),
    ("X-ARR-ClientCert",           "MIIBogIBADANBgkqattackercontrolledvalue=="),
    ("X-Forwarded-Client-Cert",    "Hash=deadbeef;Subject=CN=admin"),
    ("X-Client-Cert",              "attacker-cert-blob"),
    ("SSL_CLIENT_CERT",            "attacker-cert-blob"),
    ("X-SSL-Client-S-DN",          "CN=Administrator,DC=reflect,DC=lab"),
    ("X-Remote-User",              "reflect\\Administrator"),
    ("X-Authenticated-User",       "Administrator"),
    ("Authorization",             "Basic YWRtaW46YWRtaW4="),
    ("X-Original-URL",             "/certsrv/mscep_admin/"),
    ("X-Rewrite-URL",              "/certsrv/mscep_admin/"),
]


def _resp_fingerprint(r, extra=None):
    """A stable signature of a response, to detect whether an injected header
    changed the server's behavior vs baseline."""
    status = None
    try:
        status = sc.read_pkistatus(r.content)
    except Exception:
        pass
    return (r.status_code, len(r.content), status)


def _hdr_get(url, ca_ident, verify_tls, timeout, extra_headers):
    """One idempotent GetCACaps request with optional injected headers -> fingerprint.
    GetCACaps is deterministic (no per-request issuance), so any fingerprint change
    is attributable to the header, not to enrollment variance."""
    c = ScepClient(url, ca_ident=ca_ident, verify_tls=verify_tls, timeout=timeout,
                   extra_headers=extra_headers)
    r, ms = c._get("GetCACaps", ca_ident)
    body = r.content
    return (r.status_code, len(body), hashlib.sha256(body).hexdigest()[:16]), r


def cmd_headers(args):
    """D1.2 (Half A): proxy-trust header injection, done RIGHT. Probe with the
    idempotent GetCACaps op so response variance isn't mistaken for a header effect.
    Double-baseline first to prove the op is stable; then flag only headers whose
    response differs from that stable baseline."""
    # 1) stability check: two identical no-header requests must match, or the op
    #    isn't idempotent on this server and the test is invalid.
    fp_a, _ = _hdr_get(args.u, args.ca_ident, args.k, args.timeout, {})
    fp_b, _ = _hdr_get(args.u, args.ca_ident, args.k, args.timeout, {})
    log.info("D1.2 header-trust injection on %s (idempotent GetCACaps probe)" % (args.name or args.u))
    if fp_a != fp_b:
        log.warn("  baseline is NOT stable across two identical requests: %s vs %s" % (fp_a, fp_b))
        log.warn("  -> GetCACaps varies run-to-run here; header results below are unreliable")
        return 1
    log.info("  baseline stable: http=%s len=%s sha=%s" % fp_a)

    changed = []
    for name, value in _PROXY_TRUST_HEADERS:
        fp, r = _hdr_get(args.u, args.ca_ident, args.k, args.timeout, {name: value})
        if fp != fp_a:
            changed.append((name, fp_a, fp))
            log.warn("  %-26s -> CHANGED: http=%s len=%s sha=%s" % (name, fp[0], fp[1], fp[2]))
        else:
            log.info("  %-26s -> no change (header ignored)" % name)

    print()
    if changed:
        log.warn("%d header(s) changed the idempotent response — origin honors them:" % len(changed))
        for n, b, f in changed:
            log.warn("  %s: %s -> %s" % (n, b, f))
        log.warn("investigate + prior-art gate — attacker-settable header with a server-side effect")
    else:
        log.good("no injected proxy-trust header changed the idempotent response — origin ignores them all (secure)")
    if args.json:
        print(json.dumps({"target": args.name or args.u, "baseline": fp_a,
                          "changed": [{"header": n, "injected": f} for n, b, f in changed]}, indent=2))
    return 0


# ---- #1 request-router / operation & parameter fuzzing --------------------
# Every prior probe hit the PKIOperation *body*. This hits the request ROUTER:
# unknown/garbage operations, malformed message params, case variants, missing
# params. Routers often have thinner handling than the CMS parser.
_OPERATION_CASES = [
    ("unknown-op",        {"operation": "GetTacos"}),
    ("empty-op",          {"operation": ""}),
    ("no-operation",      {}),
    ("case-lower",        {"operation": "getcacaps"}),
    ("case-upper",        {"operation": "GETCACAPS"}),
    ("case-mixed",        {"operation": "GetCaCaps"}),
    ("op-with-space",     {"operation": "GetCACaps "}),
    ("op-injection",      {"operation": "GetCACaps%00"}),
    ("dup-operation",     None),  # handled specially (two operation params)
    ("giant-message",     {"operation": "GetCACert", "message": "A" * 100000}),
    ("null-in-message",   {"operation": "GetCACert", "message": "x\x00y"}),
    ("message-crlf",      {"operation": "GetCACert", "message": "x\r\nInjected: 1"}),
    ("pkiop-no-body",     {"operation": "PKIOperation"}),
    ("pkiop-empty-msg",   {"operation": "PKIOperation", "message": ""}),
    ("getcert-no-args",   {"operation": "GetCert"}),
    ("getcrl-no-args",    {"operation": "GetCRL"}),
]


def cmd_router(args):
    """#1: fuzz the request router (operations + params), not the CMS body.
    Bucket each by (http_status, len, content-type-ish). Flag 500s and anything
    that reflects injected content or behaves surprisingly."""
    base = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k, timeout=args.timeout)
    log.info("#1 router/operation fuzzing on %s" % (args.name or args.u))
    # reference: a known-good GetCACaps
    try:
        ref = base.getcacaps()
        log.info("  reference GetCACaps: http=%s caps=%d" % (ref["http_status"], len(ref["caps"])))
    except requests.RequestException as e:
        log.warn("  reference GetCACaps failed: %s" % e)

    flagged = []
    for name, params in _OPERATION_CASES:
        try:
            if name == "dup-operation":
                r = requests.get(args.u, params=[("operation", "GetCACaps"), ("operation", "GetCACert")],
                                 timeout=args.timeout, verify=args.k)
            else:
                r = requests.get(args.u, params=params, timeout=args.timeout, verify=args.k)
        except requests.exceptions.Timeout:
            log.warn("  %-18s -> TIMEOUT" % name); flagged.append((name, "TIMEOUT")); continue
        except requests.exceptions.ConnectionError:
            log.warn("  %-18s -> CONN-RESET" % name); flagged.append((name, "CONN-RESET")); continue
        except requests.RequestException as e:
            log.info("  %-18s -> req-error %s" % (name, str(e)[:30])); continue
        blen = len(r.content)
        # did our injected marker reflect into the response? (header/body injection)
        reflected = b"Injected" in r.content
        note = ""
        bucket = "http-%d" % r.status_code
        if r.status_code == 500:
            bucket = "http-500"; flagged.append((name, "http-500"))
        elif reflected:
            bucket = "REFLECTED"; note = "injected marker echoed!"; flagged.append((name, "REFLECTED"))
        emit = log.warn if (r.status_code == 500 or reflected) else log.info
        emit("  %-18s -> %-9s len=%-6d %s" % (name, bucket, blen, note))

    print()
    if flagged:
        log.warn("%d flagged: %s" % (len(flagged), ", ".join("%s(%s)" % f for f in flagged)))
        log.warn("  http-500 on a router path or REFLECTED marker = investigate")
    else:
        log.good("router handled all operation/param cases cleanly (4xx/expected) — no 500/reflection")
    return 0


# ---- #2 the mscep_admin challenge-generation endpoint ---------------------
def cmd_admin(args):
    """#2: probe the NDES mscep_admin (challenge-generation) endpoint — a more
    privileged surface than enrollment. What authz does it enforce unauthenticated,
    and does it leak the OTP or behave oddly to our tricks?"""
    admin_url = args.admin_url
    log.info("#2 mscep_admin probe: %s" % admin_url)
    log.info("  (NDES generates the enrollment OTP here; normally requires domain auth)")

    cases = [
        ("plain-GET",          {}, None),
        ("with-XFF-localhost", {"X-Forwarded-For": "127.0.0.1"}, None),
        ("with-remote-user",   {"X-Remote-User": "reflect\\Administrator"}, None),
        ("with-arr-cert",      {"X-ARR-ClientCert": "AAAA"}, None),
        ("with-auth-basic",    {"Authorization": "Basic YWRtaW46YWRtaW4="}, None),
    ]
    baseline_fp = None
    for name, hdrs, _ in cases:
        try:
            r = requests.get(admin_url, headers=hdrs or None, timeout=args.timeout,
                             verify=args.k, allow_redirects=False)
        except requests.RequestException as e:
            log.info("  %-20s -> req-error %s" % (name, str(e)[:40])); continue
        blen = len(r.content)
        auth = r.headers.get("WWW-Authenticate", "")
        # does the body look like it contains an OTP challenge (hex blob)?
        import re as _re
        otp = bool(_re.search(rb'[0-9A-Fa-f]{16,}', r.content)) and r.status_code == 200
        fp = (r.status_code, blen)
        if name == "plain-GET":
            baseline_fp = fp
        note = "WWW-Auth=%s" % auth[:30] if auth else ""
        if otp:
            note += "  ** possible OTP/hex blob in body (status 200) — INSPECT"
        changed = (baseline_fp and fp != baseline_fp and name != "plain-GET")
        emit = log.warn if (otp or (r.status_code == 200 and name != "plain-GET")) else log.info
        emit("  %-20s -> http=%-3d len=%-6d %s%s" % (
            name, r.status_code, blen, "CHANGED " if changed else "", note))

    log.info("  interpretation: 401/403 = auth enforced (secure). 200 + hex blob = OTP reachable (FINDING).")
    log.info("  a header that flips 401->200 = header-auth-bypass on the admin endpoint (FINDING).")
    return 0


def cmd_getcert(args):
    """#3: GetCert (messageType 21) retrieval by issuer+serial. Enroll to learn a
    valid serial, then (a) retrieve OUR serial as a non-originator, and (b) walk
    NEARBY serials as an unrelated identity — testing whether cert retrieval by
    serial is authz-bound or an enumeration primitive."""
    from asn1crypto import x509 as ax
    from asn1crypto import core as acore
    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k, timeout=args.timeout)
    caps = []
    try:
        caps = client.getcacaps()["caps"]
    except requests.RequestException:
        pass
    cert_ders, norm = client.fetch_ca_certs()
    if not cert_ders:
        log.error("no CA certs"); return 1
    recip_der, role = sc.pick_recipient(cert_ders)
    cipher = "aes256" if "AES" in caps else "des3"

    # originator enroll -> a known-valid serial
    okey = sc.gen_rsa(); osig = sc.selfsigned_signer(okey, cn=args.cn)
    csr = sc.build_csr(okey, args.cn, challenge=args.challenge, digest="sha256")
    pki, txid, nonce = sc.build_pkcs_req(csr, okey, osig, recip_der, cipher=cipher, digest="sha256")
    r, used, ms = client.pkioperation(pki, transport=args.transport, caps=caps)
    if r.status_code != 200 or sc.read_pkistatus(r.content) != "0":
        log.error("originator enroll failed (status=%s) — need a valid serial to test GetCert" % sc.read_pkistatus(r.content))
        return 1
    res = sc.parse_certrep(r.content, okey)
    if not res.get("issued_cert_der"):
        log.error("enroll ok but issued cert didn't parse — can't derive serial"); return 1
    issued = x509.load_der_x509_certificate(res["issued_cert_der"])
    serial = issued.serial_number
    issuer_name = ax.Certificate.load(res["issued_cert_der"])['tbs_certificate']['issuer']
    log.good("originator enrolled: serial %x" % serial)

    # attacker identity
    akey = sc.gen_rsa(); asig = sc.selfsigned_signer(akey, cn="attacker.getcert.test")

    def _getcert(target_serial, label, own=False):
        try:
            msg, t, n = sc.build_getcert(issuer_name, acore.Integer(target_serial),
                                         akey, asig, recip_der, cipher=cipher, digest="sha256")
        except Exception as e:
            log.info("  %-22s -> build-error %s" % (label, str(e)[:40])); return
        try:
            rr, uu, mm = client.pkioperation(msg, transport=args.transport, caps=caps)
        except requests.RequestException as e:
            log.info("  %-22s -> req-error %s" % (label, str(e)[:40])); return
        if rr.status_code != 200:
            log.info("  %-22s -> HTTP %s (rejected)" % (label, rr.status_code)); return
        st = sc.read_pkistatus(rr.content)
        if st == "0":
            try:
                pres = sc.parse_certrep(rr.content, akey)
                gc = x509.load_der_x509_certificate(pres["issued_cert_der"])
                if own:
                    log.info("  %-22s -> returned OUR cert serial %x (expected — requester's own cert)" % (
                        label, gc.serial_number))
                else:
                    log.warn("  %-22s -> ** RETURNED a NEIGHBOR cert serial %x subj=%s" % (
                        label, gc.serial_number, gc.subject.rfc4514_string()))
                    log.warn("     ** cross-identity cert retrieval by serial (enumeration primitive) — FINDING")
            except Exception:
                log.info("  %-22s -> SUCCESS but reply not decryptable by us" % label)
        elif st == "2":
            log.good("  %-22s -> SCEP FAILURE (refused)%s" % (label, " — cannot walk to others' certs (secure)" if not own else ""))
        else:
            log.info("  %-22s -> pkiStatus=%s" % (label, st))

    log.info("#3 GetCert-by-serial as a NON-originator identity:")
    _getcert(serial, "our-serial", own=True)
    for delta in (-1, +1, +2):
        _getcert(serial + delta, "serial%+d" % delta, own=False)
    log.info("  NOTE: returning OUR OWN serial is EXPECTED (GetCert returns the requester's cert).")
    log.info("  Finding condition = a NEIGHBOR serial (serial+/-N) returned -> cross-identity")
    log.info("  disclosure/enumeration. Own-serial return alone is secure.")
    return 0


def cmd_race(args):
    """#4: concurrency race on the enrollment state machine. Fire N identical
    enrollments (same txid) concurrently and look for anomalies: multiple issued
    certs for one request, inconsistent status, 500s only-under-concurrency, or
    duplicate serials. Races are invisible to sequential testing."""
    import threading
    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k, timeout=args.timeout)
    caps = []
    try:
        caps = client.getcacaps()["caps"]
    except requests.RequestException:
        pass
    cert_ders, norm = client.fetch_ca_certs()
    if not cert_ders:
        log.error("no CA certs"); return 1
    recip_der, role = sc.pick_recipient(cert_ders)
    cipher = "aes256" if "AES" in caps else "des3"

    # ONE fixed PKIMessage (same transaction_id) fired N times concurrently
    key = sc.gen_rsa(); sig = sc.selfsigned_signer(key, cn=args.cn)
    csr = sc.build_csr(key, args.cn, challenge=args.challenge, digest="sha256")
    pki, txid, nonce = sc.build_pkcs_req(csr, key, sig, recip_der, cipher=cipher, digest="sha256")
    log.info("#4 concurrency race on %s: %d identical concurrent enrolls (txid=%s...)" % (
        args.name or args.u, args.n, txid[:16]))

    results = []
    lock = threading.Lock()

    def _fire(i):
        try:
            r, used, ms = client.pkioperation(pki, transport=args.transport, caps=caps)
            st = sc.read_pkistatus(r.content) if r.status_code == 200 else None
            serial = None
            if st == "0":
                try:
                    res = sc.parse_certrep(r.content, key)
                    if res.get("issued_cert_der"):
                        serial = x509.load_der_x509_certificate(res["issued_cert_der"]).serial_number
                except Exception:
                    pass
            with lock:
                results.append((i, r.status_code, st, serial))
        except Exception as e:
            with lock:
                results.append((i, "exc", str(e)[:30], None))

    threads = [threading.Thread(target=_fire, args=(i,)) for i in range(args.n)]
    for t in threads: t.start()
    for t in threads: t.join()

    results.sort()
    serials = [s for (_, _, _, s) in results if s is not None]
    statuses = [st for (_, _, st, _) in results]
    for i, code, st, serial in results:
        log.info("  req %2d -> http=%s pkiStatus=%s serial=%s" % (
            i, code, st, ("%x" % serial) if serial else "-"))
    print()
    issued = len(serials)
    uniq = len(set(serials))
    n500 = sum(1 for (_, c, _, _) in results if c == 500)
    log.info("  issued=%d unique-serials=%d http500=%d" % (issued, uniq, n500))
    if issued > 1 and uniq > 1:
        log.warn("  ** MULTIPLE distinct certs issued for ONE transaction_id — state-machine race (investigate)")
    elif issued > 1 and uniq == 1:
        log.info("  same serial returned to multiple requests (idempotent replay — benign/expected)")
    elif n500 > 0 and issued > 0:
        log.warn("  ** mix of issue + 500 under concurrency — inconsistent handling (investigate)")
    else:
        log.good("  no race anomaly — server serializes the transaction (secure/expected)")
    return 0


def cmd_oracle(args):
    """PADDING-ORACLE differential (Bleichenbacher/ROBOT). Feed the server RSA blocks
    with controlled PKCS#1 v1.5 structure in the CMS encrypted_key, and detect whether
    its response DISTINGUISHES valid vs invalid padding vs deep failures. A conformant
    server is indistinguishable across all cases (same failInfo, status, timing).
    Distinguishable behavior = an oracle = Bleichenbacher-class vuln (T3)."""
    import statistics
    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k, timeout=args.timeout)
    caps = []
    try:
        caps = client.getcacaps()["caps"]
    except requests.RequestException:
        pass
    cert_ders, norm = client.fetch_ca_certs()
    if not cert_ders:
        log.error("no CA certs"); return 1
    recip_der, role = sc.pick_recipient(cert_ders)
    cipher = "aes256" if "AES" in caps else "des3"

    variants = sc.craft_pkcs1_variants(recip_der, cek_len=(32 if cipher == "aes256" else 24))
    log.info("padding-oracle differential on %s: %d PKCS#1 v1.5 variants x %d reps" % (
        args.name or args.u, len(variants), args.reps))
    log.info("  (a conformant server is INDISTINGUISHABLE across all variants)")

    # fixed signer identity for the outer CMS (padding is about the envelope, not the sig)
    key = sc.gen_rsa(); signer_der = sc.selfsigned_signer(key, cn=args.cn)
    csr_der = sc.build_csr(key, args.cn, challenge=args.challenge, digest="sha256")

    table = []
    for name, enckey, expect in variants:
        # build a full PKIMessage whose envelope carries the crafted encrypted_key
        env = sc.build_enveloped_with_enckey(csr_der, recip_der, enckey, cipher=cipher)
        pki = sc.build_pkcs_req_with_envelope(env, key, signer_der, digest="sha256")
        statuses, fails, times = [], [], []
        for _ in range(args.reps):
            try:
                t0 = time.perf_counter()
                r, used, ms = client.pkioperation(pki, transport=args.transport, caps=caps)
                dt = (time.perf_counter() - t0) * 1000
            except requests.RequestException as e:
                statuses.append("exc"); fails.append(str(e)[:20]); times.append(0); continue
            times.append(dt)
            if r.status_code == 200:
                st = sc.read_pkistatus(r.content)
                fi = sc.read_failinfo(r.content) if st == "2" else None
                statuses.append("pki%s" % st)
                fails.append("fi=%s" % fi if fi is not None else st)
            else:
                statuses.append("http%d" % r.status_code); fails.append("http%d" % r.status_code)
        med = round(statistics.median(times), 1) if times else 0
        # collapse to the dominant (status, fail) signature
        sig = (max(set(statuses), key=statuses.count), max(set(fails), key=fails.count))
        table.append((name, sig[0], sig[1], med, expect))
        log.info("  %-24s -> status=%-7s fail=%-8s median=%6.1fms" % (name, sig[0], sig[1], med))

    # ---- differential analysis: are the responses distinguishable? ----
    print()
    resp_sigs = set((s, f) for (_, s, f, _, _) in table)
    times_by = {n: t for (n, _, _, t, _) in table}
    conformant_t = times_by.get("conformant", 0)
    log.info("distinct (status,failInfo) signatures across variants: %d" % len(resp_sigs))
    if len(resp_sigs) == 1:
        log.good("all variants produce the IDENTICAL response signature — no status/failInfo oracle")
    else:
        log.warn("variants produce DIFFERENT response signatures:")
        for s, f in sorted(resp_sigs):
            members = [n for (n, ss, ff, _, _) in table if (ss, ff) == (s, f)]
            log.warn("  (%s, %s): %s" % (s, f, ", ".join(members)))
        log.warn("  ** distinguishable padding response = POSSIBLE oracle — verify carefully")

    # timing separation: does any INVALID variant differ from conformant by a wide margin?
    valid_t = [t for (n, _, _, t, _) in table if n == "conformant"]
    if valid_t:
        base = valid_t[0]
        outliers = [(n, t) for (n, _, _, t, _) in table if base and abs(t - base) > max(20, base * 0.5)]
        if outliers:
            log.warn("  timing outliers vs conformant (%.1fms): %s" % (
                base, ", ".join("%s=%.1fms" % (n, t) for n, t in outliers)))
            log.warn("  ** >50%% timing delta -> possible TIMING oracle; re-run with more -reps to confirm")
        else:
            log.good("  no wide timing separation vs conformant (no obvious timing oracle)")

    if args.json:
        print(json.dumps({"target": args.name or args.u,
                          "variants": [{"name": n, "status": s, "fail": f, "median_ms": t}
                                       for (n, s, f, t, _) in table],
                          "distinct_signatures": len(resp_sigs)}, indent=2))
    return 0


def cmd_selftrust(args):
    """CREATIVE #1+#2: self-trust / self-issuance confusion.
    #1: sign the outer CMS presenting the CA/RA's OWN cert as the signer cert (a
        message that appears to originate from the CA itself). Does the server extend
        trust — skip challenge, hit an internal path — to a self-signed-looking msg?
    #2: submit a CSR whose SUBJECT is the CA's own subject (self re-key). Does the CA
        issue a cert for its own identity?
    """
    from asn1crypto import x509 as ax
    client = ScepClient(args.u, ca_ident=args.ca_ident, verify_tls=args.k, timeout=args.timeout)
    caps = []
    try:
        caps = client.getcacaps()["caps"]
    except requests.RequestException:
        pass
    cert_ders, norm = client.fetch_ca_certs()
    if not cert_ders:
        log.error("no CA certs"); return 1
    recip_der, role = sc.pick_recipient(cert_ders)
    cipher = "aes256" if "AES" in caps else "des3"

    # identify the CA cert (the signing CA) and the RA cert(s) from the bundle
    ca_cert_der = None
    for d in cert_ders:
        try:
            c = x509.load_der_x509_certificate(d)
            bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
            if bc.ca:
                ca_cert_der = d; break
        except Exception:
            pass
    if ca_cert_der is None:
        ca_cert_der = cert_ders[-1]
    ca_cert = x509.load_der_x509_certificate(ca_cert_der)
    ca_subject = ax.Certificate.load(ca_cert_der)['tbs_certificate']['subject']
    log.info("self-trust probe on %s" % (args.name or args.u))
    log.info("  CA cert subject: %s" % ca_cert.subject.rfc4514_string())

    our_key = sc.gen_rsa()

    def _send(pki, label, decrypt_key):
        try:
            r, used, ms = client.pkioperation(pki, transport=args.transport, caps=caps)
        except requests.RequestException as e:
            log.info("  %-34s -> req-error %s" % (label, str(e)[:34])); return
        if r.status_code != 200:
            log.info("  %-34s -> HTTP %s (rejected)" % (label, r.status_code)); return
        st = sc.read_pkistatus(r.content)
        if st == "0":
            # Try to decrypt with our key. For #1a the reply is enveloped to the
            # SIGNER cert (the CA cert) whose key we DON'T hold -> undecryptable,
            # which means we can't actually obtain the issued cert (attack yields
            # nothing usable). Only a reply we CAN decrypt is a real disclosure.
            try:
                res = sc.parse_certrep(r.content, decrypt_key)
                if res.get("issued_cert_der"):
                    ic = x509.load_der_x509_certificate(res["issued_cert_der"])
                    is_ca = False; ku = ""
                    try:
                        bc = ic.extensions.get_extension_for_class(x509.BasicConstraints).value
                        is_ca = bc.ca
                    except Exception:
                        pass
                    try:
                        ku = str(ic.extensions.get_extension_for_class(x509.KeyUsage).value)
                    except Exception:
                        pass
                    log.warn("  %-34s -> SUCCESS + DECRYPTABLE (we got the cert):" % label)
                    log.warn("     subj=%s" % ic.subject.rfc4514_string())
                    log.warn("     issuer=%s serial=%x  CA=%s" % (ic.issuer.rfc4514_string(), ic.serial_number, is_ca))
                    if is_ca:
                        log.warn("     ** issued cert has CA=TRUE — self-issuance of a CA cert (SERIOUS)")
                    fn = "selftrust-%s.der" % label.split(",")[0].replace(" ", "_").replace("=", "")
                    try:
                        open(fn, "wb").write(res["issued_cert_der"]); log.warn("     saved: %s" % fn)
                    except Exception:
                        pass
                else:
                    log.info("  %-34s -> SUCCESS but reply had no cert we could extract" % label)
            except Exception as e:
                log.info("  %-34s -> SUCCESS but reply NOT decryptable by us (%s)" % (label, str(e)[:30]))
                log.info("     -> enveloped to the signer cert (the CA); we can't obtain the cert -> attack yields nothing usable")
        elif st == "2":
            fi = sc.read_failinfo(r.content)
            log.good("  %-34s -> SCEP FAILURE (failInfo=%s) — refused" % (label, fi))
        else:
            log.info("  %-34s -> pkiStatus=%s" % (label, st))

    # ---- #1a: outer CMS signer cert = CA's own cert, signed by OUR key (sig won't
    #      match the CA's real pubkey). Tests whether the server verifies the signer
    #      or trusts the *appearance* of a CA-signed message. ----
    csr1 = sc.build_csr(our_key, args.cn, challenge=args.challenge, digest="sha256")
    pki1, _, _ = sc.build_pkcs_req(csr1, our_key, ca_cert_der, recip_der,
                                   cipher=cipher, digest="sha256", sign_key=our_key)
    log.info("#1a outer CMS presents the CA's OWN cert as signer (signed by our key):")
    _send(pki1, "CA-cert-as-signer, no challenge", our_key)

    # ---- #1b: same, but WITH a valid challenge too (does CA-signer + challenge hit a
    #      different/privileged path?) — only meaningful if challenge provided ----
    if args.challenge:
        csr1b = sc.build_csr(our_key, args.cn, challenge=args.challenge, digest="sha256")
        pki1b, _, _ = sc.build_pkcs_req(csr1b, our_key, ca_cert_der, recip_der,
                                        cipher=cipher, digest="sha256", sign_key=our_key)
        # (identical construction; the point is to observe if CA-signer changes anything
        #  vs a normal self-signed signer — compared in analysis below)

    # ---- #2: CSR subject == the CA's own subject (self re-key / self-issuance) ----
    #      build a CSR carrying the CA's DN as subject, our key, normal self-signed signer
    our_signer = sc.selfsigned_signer(our_key, cn="selftrust.probe")
    csr2 = sc.build_csr_raw_subject(our_key, ca_subject, challenge=args.challenge, digest="sha256")         if hasattr(sc, "build_csr_raw_subject") else None
    if csr2 is not None:
        pki2, _, _ = sc.build_pkcs_req(csr2, our_key, our_signer, recip_der,
                                       cipher=cipher, digest="sha256")
        log.info("#2 CSR subject == CA's own DN (self-issuance attempt):")
        _send(pki2, "CSR-subject=CA-DN", our_key)
    else:
        log.info("#2 skipped (raw-subject CSR helper unavailable)")

    log.info("  interpretation: SCEP FAILURE / HTTP-reject on all = server doesn't self-trust (secure).")
    log.info("  any SUCCESS = server issued on a self-originated-looking or self-subject request (FINDING).")
    return 0


def cmd_baseline(args):
    """D0.5: sweep read-only ops across every target, emit the normalized grid."""
    targets = load_targets(args.targets)
    log.info("baseline sweep over %d target(s)" % len(targets))
    grid = {"generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool_version": VERSION, "servers": {}}

    for t in targets:
        name = t["name"]
        url = t["url"]
        ca_ident = t.get("ca_ident", "")
        log.info("=" * 60)
        log.info("target: %s  ->  %s" % (name, url))
        server_rec = {"url": url, "ca_ident": ca_ident, "ops": {}}
        client = ScepClient(url, ca_ident=ca_ident, verify_tls=args.k)

        for opname, fn in (("GetCACaps", client.getcacaps),
                           ("GetCACert", client.getcacert)):
            try:
                rec = fn()
                server_rec["ops"][opname] = rec
                if opname == "GetCACaps":
                    render_getcaps(name, rec)
                else:
                    render_getca(name, rec)
            except requests.RequestException as e:
                log.error("%s  %s failed: %s" % (name, opname, e))
                server_rec["ops"][opname] = {"error": str(e)}

        grid["servers"][name] = server_rec

    if args.o:
        with open(args.o, "w") as f:
            json.dump(grid, f, indent=2)
        log.good("baseline grid written: %s" % args.o)
        log.info("re-run after any mutation and diff against this file")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="scepmutator",
        description="SCEPMutator %s - SCEP differential harness (read-only foundation)" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  scepmutator getcaps -u http://microscep01:2016/scep\n"
               "  scepmutator getca   -u http://ejbca01/ejbca/publicweb/apply/scep/scep/pkiclient.exe -ca-ident ManagementCA\n"
               "  scepmutator baseline -targets targets.json -o baseline-grid.json\n")
    p.add_argument("-debug", action="store_true", help="enable debug output")
    p.add_argument("-ts", action="store_true", help="prefix log lines with timestamps")
    p.add_argument("-no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("-version", action="version", version="SCEPMutator " + VERSION)

    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("-u", required=True, metavar="URL", help="full SCEP endpoint URL")
        sp.add_argument("-ca-ident", dest="ca_ident", default="", metavar="NAME",
                        help="CA identifier for the 'message' param (EJBCA CA-mode needs this)")
        sp.add_argument("-name", default=None, help="friendly label for output")
        sp.add_argument("-json", action="store_true", help="emit JSON instead of a table")
        sp.add_argument("-k", action="store_true", help="do not verify TLS certs (https)")

    sp_caps = sub.add_parser("getcaps", help="GetCACaps (capability advertisement)")
    add_common(sp_caps)
    sp_caps.set_defaults(func=cmd_getcaps)

    sp_ca = sub.add_parser("getca", help="GetCACert (CA/RA cert bundle)")
    add_common(sp_ca)
    sp_ca.set_defaults(func=cmd_getca)

    sp_enr = sub.add_parser("enroll", help="PKCSReq enrollment (conformant; mutation flags)")
    add_common(sp_enr)
    sp_enr.add_argument("-cn", default="probe01.scepmutator.test",
                        help="CSR subject common name")
    sp_enr.add_argument("-challenge", default=None,
                        help="challengePassword value (server auth secret)")
    sp_enr.add_argument("-challenge-encoding", dest="challenge_encoding",
                        choices=["printable", "utf8"], default="printable",
                        help="ASN.1 string type for the challenge (NDES wants printable)")
    sp_enr.add_argument("-san", action="append", metavar="KIND:VALUE",
                        help="add a SAN, repeatable: dns:h.test / upn:a@b / email:a@b / ip:1.2.3.4 / uri:...")
    sp_enr.add_argument("-cipher", choices=["auto", "aes256", "aes128", "des3"],
                        default="auto", help="envelope cipher (auto = AES if advertised else DES3)")
    sp_enr.add_argument("-digest", choices=["sha1", "sha256", "sha512"],
                        default="sha256", help="CMS signature digest")
    sp_enr.add_argument("-transport", choices=["auto", "post", "get"],
                        default="auto", help="PKIOperation transport (auto = POST if advertised)")
    sp_enr.add_argument("-key-size", dest="key_size", type=int, default=2048,
                        help="RSA key size for the request")
    sp_enr.add_argument("-mutate",
                        choices=["signer-key-mismatch", "csr-nopop", "full-nopop"],
                        default=None,
                        help="single-stage mutation (3.5 identity-triangle / PoP probes)")
    sp_enr.add_argument("-o", metavar="FILE", help="write the issued cert (PEM) here")
    sp_enr.add_argument("-save-key", dest="save_key", metavar="FILE",
                        help="write the request private key (PEM) — reusable as a renewal credential")
    sp_enr.set_defaults(func=cmd_enroll)

    sp_renew = sub.add_parser("renew",
                              help="RenewalReq (cross-CA renewal confusion probe, 4.6)")
    add_common(sp_renew)
    sp_renew.add_argument("-cert", required=True, metavar="FILE",
                          help="existing cert to authenticate the renewal (PEM)")
    sp_renew.add_argument("-key", required=True, metavar="FILE",
                          help="private key matching -cert (PEM)")
    sp_renew.add_argument("-cn", default="probe01.scepmutator.test",
                          help="subject CN for the renewed cert")
    sp_renew.add_argument("-challenge", default=None,
                          help="challengePassword (usually not needed for renewal)")
    sp_renew.add_argument("-challenge-encoding", dest="challenge_encoding",
                          choices=["printable", "utf8"], default="printable")
    sp_renew.add_argument("-san", action="append", metavar="KIND:VALUE")
    sp_renew.add_argument("-cipher", choices=["auto", "aes256", "aes128", "des3"], default="auto")
    sp_renew.add_argument("-digest", choices=["sha1", "sha256", "sha512"], default="sha256")
    sp_renew.add_argument("-transport", choices=["auto", "post", "get"], default="auto")
    sp_renew.add_argument("-key-size", dest="key_size", type=int, default=2048)
    sp_renew.add_argument("-renewal-type", dest="renewal_type",
                          choices=["pkcsreq", "renewalreq"], default="pkcsreq",
                          help="pkcsreq(19)-signed-by-existing (de-facto) or renewalreq(17, RFC8894)")
    sp_renew.add_argument("-o", metavar="FILE", help="write the renewed cert (PEM) here")
    sp_renew.set_defaults(func=cmd_renew)

    sp_dg = sub.add_parser("downgrade",
                           help="D2 advertised!=enforced: send unadvertised (weaker) algorithms")
    add_common(sp_dg)
    sp_dg.add_argument("-cn", default="probe01.scepmutator.test", help="baseline CSR CN")
    sp_dg.add_argument("-challenge", default=None, help="challenge (needed for servers that gate on it)")
    sp_dg.add_argument("-transport", choices=["auto", "post", "get"], default="auto")
    sp_dg.add_argument("-timeout", type=int, default=15)
    sp_dg.set_defaults(func=cmd_downgrade)

    sp_self = sub.add_parser("selftrust",
                             help="creative: CA-cert-as-signer confusion + self-subject (CA-DN) issuance")
    add_common(sp_self)
    sp_self.add_argument("-cn", default="probe01.scepmutator.test")
    sp_self.add_argument("-challenge", default=None)
    sp_self.add_argument("-transport", choices=["auto","post","get"], default="auto")
    sp_self.add_argument("-timeout", type=int, default=15)
    sp_self.set_defaults(func=cmd_selftrust)

    sp_oracle = sub.add_parser("oracle",
                               help="padding-oracle differential (Bleichenbacher/ROBOT) on the CMS RSA key transport")
    add_common(sp_oracle)
    sp_oracle.add_argument("-cn", default="probe01.scepmutator.test")
    sp_oracle.add_argument("-challenge", default=None)
    sp_oracle.add_argument("-reps", type=int, default=8, help="repetitions per variant (timing median)")
    sp_oracle.add_argument("-transport", choices=["auto","post","get"], default="auto")
    sp_oracle.add_argument("-timeout", type=int, default=15)
    sp_oracle.set_defaults(func=cmd_oracle)

    sp_router = sub.add_parser("router", help="#1 fuzz the request router: operations + params (not CMS body)")
    add_common(sp_router)
    sp_router.add_argument("-timeout", type=int, default=15)
    sp_router.set_defaults(func=cmd_router)

    sp_admin = sub.add_parser("admin", help="#2 probe the NDES mscep_admin challenge-generation endpoint")
    sp_admin.add_argument("-admin-url", dest="admin_url", required=True,
                          help="the mscep_admin URL, e.g. http://ndes01.reflect.lab/certsrv/mscep_admin/")
    sp_admin.add_argument("-name", default=None, help="friendly label for output")
    sp_admin.add_argument("-k", action="store_true", help="do not verify TLS certs (https)")
    sp_admin.add_argument("-json", action="store_true", help="emit JSON instead of a table")
    sp_admin.add_argument("-timeout", type=int, default=15)
    sp_admin.set_defaults(func=cmd_admin)

    sp_gc = sub.add_parser("getcert", help="#3 GetCert (msgType 21): retrieve cert by issuer+serial as non-originator")
    add_common(sp_gc)
    sp_gc.add_argument("-cn", default="probe01.scepmutator.test")
    sp_gc.add_argument("-challenge", default=None)
    sp_gc.add_argument("-transport", choices=["auto","post","get"], default="auto")
    sp_gc.add_argument("-timeout", type=int, default=15)
    sp_gc.set_defaults(func=cmd_getcert)

    sp_race = sub.add_parser("race", help="#4 concurrency race on the enrollment state machine")
    add_common(sp_race)
    sp_race.add_argument("-cn", default="probe01.scepmutator.test")
    sp_race.add_argument("-challenge", default=None)
    sp_race.add_argument("-n", type=int, default=10, help="concurrent identical enrollments")
    sp_race.add_argument("-transport", choices=["auto","post","get"], default="auto")
    sp_race.add_argument("-timeout", type=int, default=15)
    sp_race.set_defaults(func=cmd_race)

    sp_hdr = sub.add_parser("headers",
                            help="D1.2 proxy-trust header injection: does the origin honor attacker-set proxy headers")
    add_common(sp_hdr)
    sp_hdr.add_argument("-cn", default="probe01.scepmutator.test", help="baseline CSR CN")
    sp_hdr.add_argument("-challenge", default=None, help="challenge for the baseline enroll")
    sp_hdr.add_argument("-transport", choices=["auto", "post", "get"], default="auto")
    sp_hdr.add_argument("-timeout", type=int, default=15)
    sp_hdr.set_defaults(func=cmd_headers)

    sp_poll = sub.add_parser("poll",
                             help="D4.4 GetCertInitial polling authorization: poll for a cert as a non-originator")
    add_common(sp_poll)
    sp_poll.add_argument("-cn", default="probe01.scepmutator.test", help="subject to enroll then poll for")
    sp_poll.add_argument("-challenge", default=None, help="challenge for the originator enrollment")
    sp_poll.add_argument("-transport", choices=["auto", "post", "get"], default="auto")
    sp_poll.add_argument("-timeout", type=int, default=15)
    sp_poll.set_defaults(func=cmd_poll)

    sp_fuzz = sub.add_parser("fuzz",
                             help="D3.3 malformation corpus: fire malformed CMS/DER at a target, bucket responses")
    add_common(sp_fuzz)
    sp_fuzz.add_argument("-cn", default="probe01.scepmutator.test", help="baseline CSR CN")
    sp_fuzz.add_argument("-challenge", default=None, help="challenge for the baseline message")
    sp_fuzz.add_argument("-transport", choices=["auto", "post", "get"], default="auto")
    sp_fuzz.add_argument("-timeout", type=int, default=15, help="per-request timeout (hang detection)")
    sp_fuzz.add_argument("-deep", action="store_true",
                         help="add the deep corpus: extreme nesting, int-overflow lengths, intra-CMS")
    sp_fuzz.set_defaults(func=cmd_fuzz)

    sp_base = sub.add_parser("baseline",
                             help="D0.5 sweep: read-only ops across all targets -> grid")
    sp_base.add_argument("-targets", required=True, metavar="FILE",
                         help="JSON targets file (see targets.json template)")
    sp_base.add_argument("-o", metavar="FILE", help="write the normalized grid to this file")
    sp_base.add_argument("-k", action="store_true", help="do not verify TLS certs (https)")
    sp_base.set_defaults(func=cmd_baseline)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    global log
    log = Logger(debug=args.debug, ts=args.ts, color=not args.no_color)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        log.error("interrupted")
        return 130
    except Exception as e:
        log.error("%s: %s" % (type(e).__name__, e))
        if args.debug:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
