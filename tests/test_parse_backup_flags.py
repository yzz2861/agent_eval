from unittest import TestCase

from webauthn.helpers import parse_backup_flags
from webauthn.helpers.parse_backup_flags import evaluate_credential_backup_state
from webauthn.helpers.structs import AuthenticatorDataFlags
from webauthn.helpers.structs import CredentialBackupStateChange, CredentialDeviceType
from webauthn.helpers.exceptions import InvalidBackupFlags


def _flags(be: bool, bs: bool) -> AuthenticatorDataFlags:
    return AuthenticatorDataFlags(
        up=True,
        uv=False,
        be=be,
        bs=bs,
        at=False,
        ed=False,
    )


class TestParseBackupFlags(TestCase):
    flags: AuthenticatorDataFlags

    def setUp(self) -> None:
        self.flags = AuthenticatorDataFlags(
            up=True,
            uv=False,
            be=False,
            bs=False,
            at=False,
            ed=False,
        )

    def test_returns_single_device_not_backed_up(self) -> None:
        self.flags.be = False
        self.flags.bs = False

        parsed = parse_backup_flags(self.flags)

        self.assertEqual(parsed.credential_device_type, "single_device")
        self.assertEqual(parsed.credential_backed_up, False)

    def test_returns_multi_device_not_backed_up(self) -> None:
        self.flags.be = True
        self.flags.bs = False

        parsed = parse_backup_flags(self.flags)

        self.assertEqual(parsed.credential_device_type, "multi_device")
        self.assertEqual(parsed.credential_backed_up, False)

    def test_returns_multi_device_backed_up(self) -> None:
        self.flags.be = True
        self.flags.bs = True

        parsed = parse_backup_flags(self.flags)

        self.assertEqual(parsed.credential_device_type, "multi_device")
        self.assertEqual(parsed.credential_backed_up, True)

    def test_raises_on_invalid_backup_state_flags(self) -> None:
        self.flags.be = False
        self.flags.bs = True

        with self.assertRaisesRegex(
            InvalidBackupFlags,
            "impossible",
        ):
            parse_backup_flags(self.flags)


class TestEvaluateCredentialBackupState(TestCase):
    def test_first_registration_accepts_all_valid_flag_combinations(self) -> None:
        cases = (
            (False, False, CredentialDeviceType.SINGLE_DEVICE, False),
            (True, False, CredentialDeviceType.MULTI_DEVICE, False),
            (True, True, CredentialDeviceType.MULTI_DEVICE, True),
        )

        for be, bs, expected_device_type, expected_backed_up in cases:
            with self.subTest(be=be, bs=bs):
                decision = evaluate_credential_backup_state(_flags(be, bs))

                self.assertTrue(decision.allowed)
                self.assertEqual(
                    decision.reason, CredentialBackupStateChange.FIRST_REGISTRATION
                )
                self.assertEqual(decision.credential_device_type, expected_device_type)
                self.assertEqual(decision.credential_backed_up, expected_backed_up)
                self.assertTrue(decision.state_changed)

    def test_first_registration_rejects_impossible_be_zero_bs_one(self) -> None:
        decision = evaluate_credential_backup_state(_flags(False, True))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, CredentialBackupStateChange.INVALID_BACKUP_FLAGS)
        self.assertFalse(decision.state_changed)

    def test_single_device_credential_stays_non_backupable(self) -> None:
        decision = evaluate_credential_backup_state(
            _flags(False, False),
            saved_device_type=CredentialDeviceType.SINGLE_DEVICE,
            saved_backed_up=False,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, CredentialBackupStateChange.SINGLE_DEVICE)
        self.assertEqual(decision.credential_device_type, CredentialDeviceType.SINGLE_DEVICE)
        self.assertFalse(decision.credential_backed_up)
        self.assertFalse(decision.state_changed)

    def test_single_device_may_gain_backup_eligibility(self) -> None:
        decision = evaluate_credential_backup_state(
            _flags(True, False),
            saved_device_type=CredentialDeviceType.SINGLE_DEVICE,
            saved_backed_up=False,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason, CredentialBackupStateChange.BACKUP_ELIGIBILITY_GAINED
        )
        self.assertEqual(decision.credential_device_type, CredentialDeviceType.MULTI_DEVICE)
        self.assertFalse(decision.credential_backed_up)
        self.assertTrue(decision.state_changed)

    def test_backup_enablement_bs_zero_to_one_is_allowed(self) -> None:
        decision = evaluate_credential_backup_state(
            _flags(True, True),
            saved_device_type=CredentialDeviceType.MULTI_DEVICE,
            saved_backed_up=False,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, CredentialBackupStateChange.BACKUP_ENABLED)
        self.assertTrue(decision.credential_backed_up)
        self.assertTrue(decision.state_changed)

    def test_backup_recovery_from_backed_up_state_is_allowed(self) -> None:
        decision = evaluate_credential_backup_state(
            _flags(True, True),
            saved_device_type=CredentialDeviceType.MULTI_DEVICE,
            saved_backed_up=True,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, CredentialBackupStateChange.BACKUP_RECOVERED)
        self.assertTrue(decision.credential_backed_up)
        self.assertFalse(decision.state_changed)

    def test_eligible_not_backed_up_state_is_unchanged(self) -> None:
        decision = evaluate_credential_backup_state(
            _flags(True, False),
            saved_device_type=CredentialDeviceType.MULTI_DEVICE,
            saved_backed_up=False,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, CredentialBackupStateChange.STATE_UNCHANGED)
        self.assertFalse(decision.state_changed)

    def test_bs_rollback_is_rejected(self) -> None:
        decision = evaluate_credential_backup_state(
            _flags(True, False),
            saved_device_type=CredentialDeviceType.MULTI_DEVICE,
            saved_backed_up=True,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, CredentialBackupStateChange.BACKUP_STATE_ROLLBACK)
        self.assertFalse(decision.state_changed)

    def test_be_rollback_is_rejected_as_clone_suspected(self) -> None:
        decision = evaluate_credential_backup_state(
            _flags(False, False),
            saved_device_type=CredentialDeviceType.MULTI_DEVICE,
            saved_backed_up=False,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason, CredentialBackupStateChange.BACKUP_ELIGIBILITY_ROLLBACK
        )
        self.assertFalse(decision.state_changed)

    def test_be_rollback_from_backed_up_state_is_also_rejected(self) -> None:
        decision = evaluate_credential_backup_state(
            _flags(False, False),
            saved_device_type=CredentialDeviceType.MULTI_DEVICE,
            saved_backed_up=True,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason, CredentialBackupStateChange.BACKUP_ELIGIBILITY_ROLLBACK
        )
