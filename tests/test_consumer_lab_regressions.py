# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Consumer security regressions using real ES10b APDUs and protected BPPs.

These are component tests. The independent lab scripts exercise HTTPS ES9+.
"""
import datetime
import json
import os
from pathlib import Path
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from SIMCARD.engine import SimulatedSimCardEngine
from pySim.esim import rsp
from tests.test_simcard_backend import (
    build_authenticate_server_payload, build_prepare_download_payload,
    build_signed_bpp_segments, build_minimal_saip_upp, extract_euicc_challenge,
    find_first_tlv, read_tlv, send_store_data_payload, verify_raw_ecdsa_signature,
)

LAB = Path(os.environ.get('ESIMULACRUM_ROOT', Path(__file__).resolve().parents[2]))
CERT = LAB / 'build/state/certs'

@pytest.fixture
def card(tmp_path, monkeypatch, request):
    for key in list(os.environ):
        if key.startswith('YGGDRASIM_SIM_'):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('YGGDRASIM_RUNTIME_ROOT', str(tmp_path / 'runtime'))
    monkeypatch.setenv('YGGDRASIM_SIM_CI_CERT_PATH', str(CERT / 'CertificateIssuer/CERT_CI_ECDSA_NIST.pem'))
    monkeypatch.setenv('YGGDRASIM_SIM_QUIRKS', 'NONE')
    monkeypatch.setenv('YGGDRASIM_SIM_BEHAVIOUR_PROFILE', 'NONE')
    engine = SimulatedSimCardEngine(isdr_config_path=str(LAB / 'fixtures/isdr.json'),
        euicc_store_root=str(tmp_path / 'euicc'), profile_store_path=str(tmp_path / 'profiles'))
    apdus = []
    class Connection:
        def transmit(self, apdu):
            data, sw1, sw2 = engine.transmit(bytes(apdu))
            apdus.append({'command': bytes(apdu).hex(), 'response': data.hex(), 'sw': f'{sw1:02x}{sw2:02x}'})
            return list(data), sw1, sw2
    conn = Connection()
    conn.transmit(bytes.fromhex('00A4040010A0000005591010FFFFFFFF8900000100'))
    material = {}
    for role, stem in [('auth', 'DPauth/SM_DPauth'), ('pb', 'DPpb/SM_DPpb')]:
        directory, name = stem.split('/')
        material[role + '_cert'] = (CERT / directory / f'CERT_S_{name}_ECDSA_NIST.der').read_bytes()
        material[role + '_key'] = serialization.load_pem_private_key(
            (CERT / directory / f'SK_S_{name}_ECDSA_NIST.pem').read_bytes(), None)
    data, _, _ = conn.transmit(bytes.fromhex('80E2910003BF2E00'))
    obj = {'engine': engine, 'conn': conn, 'material': material,
           'tx': bytes(range(16)), 'challenge': extract_euicc_challenge(data),
           'before': [p.iccid for p in engine.state.profiles]}
    yield obj
    assert [p.iccid for p in engine.state.profiles] == obj['before']
    reloaded = SimulatedSimCardEngine(isdr_config_path=str(LAB / 'fixtures/isdr.json'),
        euicc_store_root=str(tmp_path / 'euicc'), profile_store_path=str(tmp_path / 'profiles'))
    assert [p.iccid for p in reloaded.state.profiles] == obj['before']
    log = LAB / 'build/logs/regression-apdus'
    log.mkdir(parents=True, exist_ok=True)
    (log / (request.node.name + '.json')).write_text(json.dumps(apdus, indent=2))

def authenticate(c, **changes):
    args = dict(transaction_id=c['tx'], euicc_challenge=c['challenge'],
                server_address='testsmdpplus1.example.com', server_challenge=b'x' * 16,
                root_ci_id=c['engine'].state.root_ci_pkid,
                ctx_params=rsp.asn1.encode('CtxParams1', ('ctxParamsForCommonAuthentication',
                    {'matchingId': 'regression', 'deviceInfo': {'tac': bytes(8), 'deviceCapabilities': {}}})),
                cert_der=c['material']['auth_cert'], cert_private_key=c['material']['auth_key'])
    args.update(changes)
    raw, _, _ = send_store_data_payload(c['conn'], build_authenticate_server_payload(**args))
    return raw

def prepare(c, **changes):
    auth = authenticate(c)
    assert rsp.asn1.decode('AuthenticateServerResponse', auth)[0] == 'authenticateResponseOk'
    _, sig, _, _ = read_tlv(find_first_tlv(auth, '5F37'))
    args = dict(transaction_id=c['tx'], euicc_signature1=sig,
                cert_der=c['material']['pb_cert'], cert_private_key=c['material']['pb_key'])
    args.update(changes)
    raw, _, _ = send_store_data_payload(c['conn'], build_prepare_download_payload(**args))
    return raw

def package(c, **changes):
    prepared = prepare(c)
    assert rsp.asn1.decode('PrepareDownloadResponse', prepared)[0] == 'downloadResponseOk'
    args = dict(transaction_id=c['tx'], euicc_otpk_raw=find_first_tlv(prepared, '5F49'),
                eid_hex=c['engine'].state.eid, cert_private_key=c['material']['pb_key'],
                iccid='89000123456789019991', provider_name='TEST ONLY', profile_name='Regression')
    args.update(changes)
    return build_signed_bpp_segments(**args)

def result(raw):
    decoded = rsp.asn1.decode('ProfileInstallationResult', raw)
    kind, details = decoded['profileInstallationResultData']['finalResult']
    assert kind == 'errorResult'
    return details['bppCommandId'], details['errorReason']

def install(c, p, target='a3'):
    for key in ('bootstrap', 'a0', 'a1', 'a3'):
        raw, sw1, sw2 = send_store_data_payload(c['conn'], p[key])
        assert (sw1, sw2) == (0x90, 0x00)
        if key == target:
            return raw

@pytest.mark.parametrize('case, expected', [('signature', 2), ('challenge', 6), ('untrusted-ci', 7)])
def test_authentication_rejections(card, case, expected):
    changes = {'signature_override': b'\xff' * 64} if case == 'signature' else (
              {'euicc_challenge': b'\xff' * 16} if case == 'challenge' else {'root_ci_id': b'\xff' * 20})
    kind, info = rsp.asn1.decode('AuthenticateServerResponse', authenticate(card, **changes))
    assert kind == 'authenticateResponseError'
    assert info['authenticateErrorCode'] == expected

def test_forged_ci_identifier_does_not_establish_trust(card):
    original = x509.load_der_x509_certificate(card['material']['auth_cert'])
    attacker = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(original.subject).issuer_name(original.issuer)
         .public_key(attacker.public_key()).serial_number(10)
         .not_valid_before(datetime.datetime(2026, 1, 1)).not_valid_after(datetime.datetime(2030, 1, 1)))
    for ext in original.extensions:
        b = b.add_extension(ext.value, ext.critical)
    forged = b.sign(attacker, hashes.SHA256())  # Copies trusted AKI, lacks CI signature.
    kind, info = rsp.asn1.decode('AuthenticateServerResponse', authenticate(card,
        cert_der=forged.public_bytes(serialization.Encoding.DER), cert_private_key=attacker))
    assert kind == 'authenticateResponseError' and info['authenticateErrorCode'] == 1

def test_prepare_wrong_transaction(card):
    kind, info = rsp.asn1.decode('PrepareDownloadResponse', prepare(card, transaction_id=b'bad'))
    assert kind == 'downloadResponseError' and info['downloadErrorCode'] == 5

@pytest.mark.parametrize('case, expected', [
    ('mac', (2, 8)), ('ciphertext', (5, 8)), ('binding', (1, 8)),
    ('signature', (0, 2)), ('transaction', (0, 3)), ('truncated', (5, 7)),
    ('malformed-profile', (5, 12)), ('truncated-profile', (5, 12)), ('duplicate', (5, 9))])
def test_protected_package_rejections(card, case, expected):
    kwargs = {}
    if case == 'binding':
        kwargs['eid_hex'] = '89049032000000000000000000000002'
    elif case == 'transaction':
        kwargs['transaction_id'] = b'bad'
    elif case == 'malformed-profile':
        kwargs['upp_payload'] = b'garbage'
    elif case == 'truncated-profile':
        kwargs['upp_payload'] = build_minimal_saip_upp(iccid='89000123456789019991',
            imsi='001010123456789', impi='test@example.test', profile_name='Truncated')[:-1]
    elif case == 'duplicate':
        kwargs['iccid'] = card['before'][0]
    p = package(card, **kwargs)
    target = 'a3'
    if case in ('mac', 'ciphertext', 'signature'):
        key = {'mac': 'a1', 'ciphertext': 'a3', 'signature': 'bootstrap'}[case]
        value = bytearray(p[key])
        value[-1 if case != 'ciphertext' else 6] ^= 1
        p[key] = bytes(value)
        target = key
    elif case == 'truncated':
        p['a3'] = p['a3'][:-1]
    elif case in ('binding', 'transaction'):
        target = 'a0' if case == 'binding' else 'bootstrap'
    raw = install(card, p, target)
    assert result(raw) == expected
    assert card['engine'].state.sgp_session.prepare_download_done is False

def test_profile_interpreter_absence_fails_closed(card):
    p = package(card)
    with mock.patch('SIMCARD.saip_profile._get_saip_asn1', return_value=None):
        assert result(install(card, p)) == (5, 12)

def test_installation_result_signature_and_layout(card):
    s = card['engine'].sgp
    s.state.sgp_session.transaction_id = card['tx']
    raw = s._profile_installation_result(success=True, result_code=5, result_detail=0,
        aid=bytes.fromhex(s.state.profiles[0].aid))
    decoded = rsp.asn1.decode('ProfileInstallationResult', raw)
    assert decoded['profileInstallationResultData']['finalResult'][0] == 'successResult'
    verify_raw_ecdsa_signature(x509.load_der_x509_certificate(s._current_euicc_certificate_der()),
                              find_first_tlv(raw, 'BF27'), decoded['euiccSignPIR'])

def test_notifications_preserve_configured_https_port():
    from SCP11.live.es9_client import Es9LikeClient
    client = Es9LikeClient('https://testsmdpplus1.example.com:8443')
    assert client._resolve_handle_notification_base_url('testsmdpplus1.example.com') == client.get_base_url()
    assert client._resolve_handle_notification_base_url('other.example.com') == 'https://other.example.com'

def test_profile_enumeration_uses_standard_asn1(card):
    raw, _, _ = send_store_data_payload(card['conn'], bytes.fromhex('BF2D00'))
    kind, profiles = rsp.asn1.decode('ProfileInfoListResponse', raw)
    assert kind == 'profileInfoListOk' and len(profiles) == len(card['before'])

def test_challenges_are_fresh_with_identical_identity_and_apdu_count(card):
    engine = card['engine']
    engine.state.apdu_count = 10
    first = engine.sgp._issue_card_challenge()
    engine.state.apdu_count = 10
    second = engine.sgp._issue_card_challenge()
    assert len(first) == len(second) == 16 and first != second

def test_lpa_does_not_report_success_for_an_empty_install_result(monkeypatch):
    # A mocked LPA response test, distinct from the APDU/crypto component tests.
    from SCP11.live.orchestrator import SGP22Orchestrator
    from tests.test_scp11_orchestrator import FakeCfg, FakeApduChannel
    orch = SGP22Orchestrator(FakeCfg(), FakeApduChannel())
    orch.state.bpp_bytes = b'fixture'
    monkeypatch.setattr(orch, '_segment_bound_profile_package', lambda b: [b'fixture'])
    monkeypatch.setattr(orch, '_inspect_install_bootstrap', lambda b: None)
    monkeypatch.setattr(orch, '_send_personalization_store_data', lambda *a, **kw: b'')
    with pytest.raises(RuntimeError, match='without a ProfileInstallationResult'):
        orch._phase_install_package()
