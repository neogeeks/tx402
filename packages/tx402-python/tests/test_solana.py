"""The Solana / SVM adapter (SPEC §7.2, ADR-013).

The four ``svm.authorization-plan`` vectors freeze the plan derivation; this suite covers
what surrounds it — the RPC cluster boundary, the pre-sign transaction validator, and the
signer contract. The validator is the part that most needs the coverage: it is the last
thing that runs before a caller's key is asked to authorize a transfer.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from typing import Any, Literal

import httpx
import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

import tx402.solana
from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.errors import (
    ConfigurationError,
    InvalidPaymentRequiredError,
    SignerError,
    Tx402ErrorContext,
)
from tx402.health import HealthIndex
from tx402.solana import (
    COMPUTE_BUDGET_PROGRAM_ADDRESS,
    MEMO_PROGRAM_ADDRESS,
    SOLANA_WIRE_TRANSACTION_MAX_BYTES,
    TOKEN_PROGRAM_ADDRESS,
    ExactSvmPlan,
    SolanaSignerPresentation,
    SolanaSignRequest,
    SvmRpcError,
    SvmRpcPool,
    build_exact_svm_message,
    create_svm_authorization,
    derive_associated_token_account,
    is_solana_signer,
    plan_exact_svm_authorization,
    resolve_solana_public_key,
)

DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
DEVNET_GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
NETWORK: Any = BUNDLED_MANIFEST["networks"][DEVNET]
ASSET: Any = NETWORK["assets"][0]
MINT = ASSET["mint"]
PAYER = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
RECIPIENT = "11111111111111111111111111111111"
BLOCKHASH = "11111111111111111111111111111111"
NOW = 1_785_715_200_000


def context() -> Tx402ErrorContext:
    return Tx402ErrorContext(request_id="test", phase="sign")


def requirement(**overrides: Any) -> dict[str, Any]:
    extra: dict[str, Any] = {"feePayer": RECIPIENT, "memo": "tx402-test"}
    extra.update(overrides.pop("extra", {}))
    document: dict[str, Any] = {
        "index": 0,
        "scheme": "exact",
        "network": DEVNET,
        "asset": MINT,
        "amountAtomic": "50000",
        "payTo": RECIPIENT,
        "maxTimeoutSeconds": 60,
        "extra": extra,
    }
    document.update(overrides)
    return document


def plan(**overrides: Any) -> ExactSvmPlan:
    return plan_exact_svm_authorization(
        requirement=requirement(**overrides),
        network_id=DEVNET,
        network=NETWORK,
        asset=ASSET,
        payer=PAYER,
        context=context(),
    )


class Signer:
    kind: Literal["solana"] = "solana"

    def __init__(self, signature: object = b"\x01" * 64, public_key: str = PAYER) -> None:
        self._signature = signature
        self._public_key = public_key
        self.requests: list[SolanaSignRequest] = []

    def get_public_key(self) -> str:
        return self._public_key

    def sign_transaction(self, request: SolanaSignRequest) -> bytes:
        self.requests.append(request)
        return self._signature  # type: ignore[return-value]


def presentation() -> SolanaSignerPresentation:
    return SolanaSignerPresentation(
        network=DEVNET,
        asset_id=f"{DEVNET}/token:{MINT}",
        asset_symbol="USDC",
        amount_decimal="0.05",
        amount_atomic="50000",
        recipient=RECIPIENT,
        resource_host="merchant.test",
        fee_payer=RECIPIENT,
        source_token_account=derive_associated_token_account(mint=MINT, owner=PAYER),
        destination_token_account=derive_associated_token_account(
            mint=MINT, owner=RECIPIENT
        ),
        last_valid_block_height="0",
        request_hash="sha256:0",
    )


#: The merchant-supplied memo every fixture here uses, so the builder is deterministic.
MEMO = b"tx402-test"


def force_message(monkeypatch: pytest.MonkeyPatch, message: MessageV0) -> None:
    """Makes the builder return ``message``, so the validator is tested against the wire.

    The validator decodes the serialized bytes rather than reading the builder's own
    objects, which is the only arrangement in which a construction bug fails a test instead
    of agreeing with it.
    """
    monkeypatch.setattr(tx402.solana, "build_exact_svm_message", lambda *_args: message)


def sign(
    plan_override: ExactSvmPlan | None = None, signer: Signer | None = None
) -> tuple[dict[str, Any], int]:
    return create_svm_authorization(
        signer=signer or Signer(),
        plan=plan_override or plan(),
        blockhash=BLOCKHASH,
        presentation=presentation(),
        lifetime_seconds=60,
        context=context(),
    )


# ----------------------------------------------------------------------------------------
# Planning
# ----------------------------------------------------------------------------------------


class TestPlanning:
    def test_derives_the_canonical_payment_atas(self) -> None:
        derived = plan()
        assert derived.source_token_account == derive_associated_token_account(
            mint=MINT, owner=PAYER
        )
        assert derived.destination_token_account == derive_associated_token_account(
            mint=MINT, owner=RECIPIENT
        )
        assert derived.genesis_hash == DEVNET_GENESIS

    def test_lifetime_never_exceeds_the_merchant_bound(self) -> None:
        """SPEC §6.6: ``min(60, merchant bound)``, and the merchant's value is a ceiling."""
        assert plan(maxTimeoutSeconds=15).lifetime_seconds == 15
        assert plan(maxTimeoutSeconds=600).lifetime_seconds == 60

    @pytest.mark.parametrize(
        ("overrides", "reason"),
        [
            ({"extra": {"feePayer": None}}, "svm-feePayer-missing"),
            ({"extra": {"feePayer": "not-base58!"}}, "svm-feePayer-invalid"),
            ({"payTo": "not-base58!"}, "svm-pay-to-invalid"),
            ({"scheme": "upto"}, "svm-route-mismatch"),
            ({"asset": RECIPIENT}, "svm-route-mismatch"),
            ({"network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}, "svm-route-mismatch"),
        ],
    )
    def test_rejects_unusable_requirements(
        self, overrides: dict[str, Any], reason: str
    ) -> None:
        with pytest.raises(InvalidPaymentRequiredError) as raised:
            plan(**overrides)
        assert raised.value.details["reason"] == reason

    def test_an_invalid_payer_is_rejected_before_any_derivation(self) -> None:
        with pytest.raises(InvalidPaymentRequiredError) as raised:
            plan_exact_svm_authorization(
                requirement=requirement(),
                network_id=DEVNET,
                network=NETWORK,
                asset=ASSET,
                payer="not-base58!",
                context=context(),
            )
        assert raised.value.details["reason"] == "svm-payer-invalid"

    def test_token_2022_is_excluded_at_planning_not_at_signing(self) -> None:
        """SPEC §7.2. Rejecting here means no balance read is spent on it either."""
        with pytest.raises(ConfigurationError) as raised:
            plan_exact_svm_authorization(
                requirement=requirement(),
                network_id=DEVNET,
                network=NETWORK,
                asset={**ASSET, "tokenProgram": "token-2022"},
                payer=PAYER,
                context=context(),
            )
        assert raised.value.details["reason"] == "token-2022-excluded"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("999999", "999999"), (42, "42"), ("007", "0"), (None, "0"), (-1, "0")],
    )
    def test_last_valid_block_height_is_a_normalized_unsigned_string(
        self, value: object, expected: str
    ) -> None:
        assert (
            plan(extra={"lastValidBlockHeight": value}).last_valid_block_height == expected
        )

    def test_the_plan_dict_omits_absent_optional_members(self) -> None:
        """The frozen fixture shape never carries an explicit null."""
        document = plan(extra={"memo": None}).to_dict()
        assert "memo" not in document
        assert "recentBlockhash" not in document


# ----------------------------------------------------------------------------------------
# Transaction construction and the pre-sign boundary
# ----------------------------------------------------------------------------------------


class TestTransaction:
    def test_reproduces_the_upstream_instruction_layout(self) -> None:
        """A facilitator must not be able to tell a tx402 payload from an upstream one."""
        message = build_exact_svm_message(plan(), BLOCKHASH, b"tx402-test")
        keys = list(message.account_keys)
        programs = [str(keys[item.program_id_index]) for item in list(message.instructions)]
        assert programs == [
            COMPUTE_BUDGET_PROGRAM_ADDRESS,
            COMPUTE_BUDGET_PROGRAM_ADDRESS,
            TOKEN_PROGRAM_ADDRESS,
            MEMO_PROGRAM_ADDRESS,
        ]
        # The facilitator's fee payer is signature slot 0; the buyer's authority is slot 1.
        assert str(keys[0]) == RECIPIENT
        assert message.header.num_required_signatures == 2

    def test_the_transfer_carries_the_approved_amount_and_decimals(self) -> None:
        message = build_exact_svm_message(plan(), BLOCKHASH, b"m")
        transfer = list(message.instructions)[2]
        data = bytes(transfer.data)
        assert data[0] == 12  # TransferChecked
        assert int.from_bytes(data[1:9], "little") == 50_000
        assert data[9] == 6

    def test_signs_the_versioned_message_bytes_and_fills_only_slot_one(self) -> None:
        signer = Signer()
        payload, expires = sign(signer=signer)
        request = signer.requests[0]
        # The bytes Ed25519 covers are the compiled message behind its 0x80 version prefix.
        assert request.message_bytes[0] == 0x80
        assert expires > 0

        decoded = VersionedTransaction.from_bytes(base64.b64decode(payload["transaction"]))
        signatures = list(decoded.signatures)
        assert signatures[0] == Signature.default()
        assert bytes(signatures[1]) == b"\x01" * 64

    def test_a_merchant_memo_is_used_verbatim_and_a_missing_one_is_a_fresh_nonce(
        self,
    ) -> None:
        with_memo = build_exact_svm_message(plan(), BLOCKHASH, b"tx402-test")
        assert bytes(list(with_memo.instructions)[3].data) == b"tx402-test"

        # Without a merchant memo every authorization gets its own 16-byte nonce, so a
        # re-challenge can never re-send the same transaction.
        anonymous = plan(extra={"memo": None})
        first = sign(anonymous)[0]["transaction"]
        second = sign(anonymous)[0]["transaction"]
        assert first != second

    def test_an_oversized_merchant_memo_is_refused(self) -> None:
        with pytest.raises(SignerError) as raised:
            sign(plan(extra={"memo": "x" * 300}))
        assert raised.value.details["causeCategory"] == "plan-mismatch"

    @pytest.mark.parametrize(
        ("mutation", "category"),
        [
            ({"fee_payer": PAYER}, "plan-mismatch"),
            ({"payer": RECIPIENT}, "plan-mismatch"),
            ({"amount_atomic": "1"}, "plan-mismatch"),
            ({"decimals": 9}, "plan-mismatch"),
            ({"source_token_account": RECIPIENT}, "plan-mismatch"),
            ({"destination_token_account": RECIPIENT}, "plan-mismatch"),
        ],
    )
    def test_the_validator_rejects_a_transaction_that_left_the_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mutation: dict[str, Any],
        category: str,
    ) -> None:
        """The validator re-reads the serialized bytes, so a construction bug cannot agree
        with itself: the plan is compared against what the *wire* says.
        """
        approved = plan()
        signer = Signer()
        # Build against the approved plan, then validate against a different one — exactly
        # the shape of a scheme that quietly changed a field after approval.
        force_message(monkeypatch, build_exact_svm_message(approved, BLOCKHASH, MEMO))

        with pytest.raises(SignerError) as raised:
            create_svm_authorization(
                signer=signer,
                plan=replace(approved, **mutation),
                blockhash=BLOCKHASH,
                presentation=presentation(),
                lifetime_seconds=60,
                context=context(),
            )
        assert raised.value.details["causeCategory"] == category
        assert signer.requests == [], "the signer must never be reached"

    def test_a_blockhash_mismatch_is_refused_before_signing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        signer = Signer()
        force_message(monkeypatch, build_exact_svm_message(plan(), BLOCKHASH, MEMO))
        other = str(Hash.from_string("So11111111111111111111111111111111111111112"))

        with pytest.raises(SignerError) as raised:
            create_svm_authorization(
                signer=signer,
                plan=plan(),
                blockhash=other,
                presentation=presentation(),
                lifetime_seconds=60,
                context=context(),
            )
        assert raised.value.details["causeCategory"] == "plan-mismatch"
        assert signer.requests == []

    def test_an_unsupported_program_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rogue = MessageV0.try_compile(
            payer=Pubkey.from_string(RECIPIENT),
            instructions=[
                Instruction(
                    program_id=Pubkey.from_string(TOKEN_PROGRAM_ADDRESS),
                    accounts=[
                        AccountMeta(
                            Pubkey.from_string(PAYER), is_signer=True, is_writable=True
                        )
                    ],
                    data=bytes([12]) + (1).to_bytes(8, "little") + bytes([6]),
                )
            ]
            * 4,
            address_lookup_table_accounts=[],
            recent_blockhash=Hash.from_string(BLOCKHASH),
        )
        force_message(monkeypatch, rogue)

        with pytest.raises(SignerError) as raised:
            sign()
        assert raised.value.details["causeCategory"] == "account-constraints"

    def test_an_instruction_count_that_is_not_four_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        short = MessageV0.try_compile(
            payer=Pubkey.from_string(RECIPIENT),
            instructions=[
                Instruction(
                    program_id=Pubkey.from_string(COMPUTE_BUDGET_PROGRAM_ADDRESS),
                    accounts=[],
                    data=bytes([2]) + (20_000).to_bytes(4, "little"),
                )
            ],
            address_lookup_table_accounts=[],
            recent_blockhash=Hash.from_string(BLOCKHASH),
        )
        force_message(monkeypatch, short)

        with pytest.raises(SignerError) as raised:
            sign()
        assert raised.value.details["causeCategory"] == "account-constraints"

    def test_the_wire_size_limit_is_enforced(self) -> None:
        assert SOLANA_WIRE_TRANSACTION_MAX_BYTES == 1232
        payload, _expires = sign()
        assert len(base64.b64decode(payload["transaction"])) <= 1232

    def test_a_malformed_blockhash_is_a_typed_construction_failure(self) -> None:
        with pytest.raises(SignerError) as raised:
            create_svm_authorization(
                signer=Signer(),
                plan=plan(),
                blockhash="not-a-hash!",
                presentation=presentation(),
                lifetime_seconds=60,
                context=context(),
            )
        assert raised.value.details["causeCategory"] == "payload-creation-failed"


# ----------------------------------------------------------------------------------------
# Signer contract
# ----------------------------------------------------------------------------------------


class TestSigner:
    def test_structural_detection_accepts_a_plain_object(self) -> None:
        assert is_solana_signer(Signer())
        assert not is_solana_signer(object())
        assert not is_solana_signer(None)

    def test_resolves_and_normalizes_the_public_key(self) -> None:
        assert resolve_solana_public_key(Signer(), context()) == PAYER

    @pytest.mark.parametrize("value", ["not-base58!", 42])
    def test_a_malformed_public_key_is_typed(self, value: object) -> None:
        with pytest.raises(SignerError) as raised:
            resolve_solana_public_key(Signer(public_key=value), context())  # type: ignore[arg-type]
        assert raised.value.details["causeCategory"] == "address-unavailable"

    def test_a_failing_public_key_lookup_is_typed(self) -> None:
        class Broken(Signer):
            def get_public_key(self) -> str:
                raise RuntimeError("kms offline")

        with pytest.raises(SignerError) as raised:
            resolve_solana_public_key(Broken(), context())
        assert raised.value.details["causeCategory"] == "address-unavailable"

    @pytest.mark.parametrize("signature", [b"short", "0xnotbytes", None])
    def test_a_malformed_signature_is_refused(self, signature: object) -> None:
        with pytest.raises(SignerError) as raised:
            sign(signer=Signer(signature=signature))
        assert raised.value.details["causeCategory"] == "signature-malformed"

    def test_a_rejecting_signer_is_typed_without_leaking_its_message(self) -> None:
        class Rejecting(Signer):
            def sign_transaction(self, request: SolanaSignRequest) -> bytes:
                raise RuntimeError("secret-key-path=/home/user/.config")

        with pytest.raises(SignerError) as raised:
            sign(signer=Rejecting())
        assert raised.value.details["causeCategory"] == "signing-failed"
        assert "secret-key-path" not in raised.value.to_dict()["message"]

    def test_the_presentation_reaches_the_signer(self) -> None:
        """SPEC §6.6: a person must be able to check what they are approving."""
        signer = Signer()
        sign(signer=signer)
        shown = signer.requests[0].presentation
        assert shown.amount_decimal == "0.05"
        assert shown.asset_symbol == "USDC"
        assert shown.recipient == RECIPIENT
        assert shown.resource_host == "merchant.test"


# ----------------------------------------------------------------------------------------
# RPC pool
# ----------------------------------------------------------------------------------------


def token_account_response(
    owner: str = PAYER, mint: str = MINT, amount: str = "5000000", decimals: int = 6
) -> dict[str, Any]:
    return {
        "value": {
            "owner": TOKEN_PROGRAM_ADDRESS,
            "data": {
                "parsed": {
                    "info": {
                        "owner": owner,
                        "mint": mint,
                        "tokenAmount": {"amount": amount, "decimals": decimals},
                    }
                }
            },
        }
    }


def rpc(handlers: dict[str, Any], *, genesis: str = DEVNET_GENESIS) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        document = json.loads(request.read())
        method = document["method"]
        host = request.url.host
        result = handlers.get(f"{host}:{method}", handlers.get(method))
        if result is None and method == "getGenesisHash":
            result = genesis
        if isinstance(result, httpx.Response):
            return result
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": document["id"], "result": result}
        )

    return httpx.MockTransport(handle)


class TestRpcPool:
    def test_proves_genesis_on_the_same_endpoint_that_serves_the_balance(self) -> None:
        seen: list[str] = []

        def handle(request: httpx.Request) -> httpx.Response:
            document = json.loads(request.read())
            seen.append(f"{request.url.host}:{document['method']}")
            result = (
                DEVNET_GENESIS
                if document["method"] == "getGenesisHash"
                else token_account_response()
            )
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

        pool = SvmRpcPool(
            ["https://a.test", "https://b.test"],
            network_id=DEVNET,
            transport=httpx.MockTransport(handle),
        )
        reading = pool.read_balance(
            genesis_hash=DEVNET_GENESIS,
            mint=MINT,
            owner=PAYER,
            decimals=6,
            now_epoch_ms=NOW,
        )
        assert reading.balance_atomic == 5_000_000
        assert seen == ["a.test:getGenesisHash", "a.test:getAccountInfo"]

    def test_a_wrong_cluster_opens_the_circuit_and_fails_over(self) -> None:
        """SPEC §7.2: the wrong cluster is not a reliability sample to average."""
        health = HealthIndex()
        transport = rpc(
            {
                "a.test:getGenesisHash": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
                "getAccountInfo": token_account_response(),
            }
        )
        pool = SvmRpcPool(
            ["https://a.test", "https://b.test"],
            network_id=DEVNET,
            health=health,
            transport=transport,
        )
        reading = pool.read_balance(
            genesis_hash=DEVNET_GENESIS,
            mint=MINT,
            owner=PAYER,
            decimals=6,
            now_epoch_ms=NOW,
        )
        assert reading.endpoint == "b.test"
        assert health.state(HealthIndex.endpoint_id(DEVNET, "a.test"), NOW) == "open"

    def test_a_missing_ata_is_a_real_zero_balance(self) -> None:
        """An ATA that never received the token does not exist on chain."""
        pool = SvmRpcPool(
            ["https://a.test"],
            network_id=DEVNET,
            transport=rpc({"getAccountInfo": {"value": None}}),
        )
        reading = pool.read_balance(
            genesis_hash=DEVNET_GENESIS,
            mint=MINT,
            owner=PAYER,
            decimals=6,
            now_epoch_ms=NOW,
        )
        assert reading.balance_atomic == 0

    @pytest.mark.parametrize(
        "value",
        [
            {"value": {"owner": "SomeOtherProgram1111111111111111111111111111"}},
            {"value": {"owner": TOKEN_PROGRAM_ADDRESS, "data": {}}},
            {"nope": 1},
        ],
    )
    def test_an_account_that_is_not_this_ata_is_refused(self, value: Any) -> None:
        pool = SvmRpcPool(
            ["https://a.test"], network_id=DEVNET, transport=rpc({"getAccountInfo": value})
        )
        with pytest.raises(SvmRpcError) as raised:
            pool.read_balance(
                genesis_hash=DEVNET_GENESIS,
                mint=MINT,
                owner=PAYER,
                decimals=6,
                now_epoch_ms=NOW,
            )
        assert raised.value.failure == "account-unreadable"

    @pytest.mark.parametrize(
        "overrides",
        [
            {"owner": RECIPIENT},
            {"mint": RECIPIENT},
            {"decimals": 9},
            {"amount": "not-a-number"},
        ],
    )
    def test_ata_contents_must_match_the_route(self, overrides: dict[str, Any]) -> None:
        pool = SvmRpcPool(
            ["https://a.test"],
            network_id=DEVNET,
            transport=rpc({"getAccountInfo": token_account_response(**overrides)}),
        )
        with pytest.raises(SvmRpcError) as raised:
            pool.read_balance(
                genesis_hash=DEVNET_GENESIS,
                mint=MINT,
                owner=PAYER,
                decimals=6,
                now_epoch_ms=NOW,
            )
        assert raised.value.failure == "account-unreadable"

    @pytest.mark.parametrize(
        ("response", "failure"),
        [
            (httpx.Response(503), "transport"),
            (httpx.Response(200, content=b"no"), "protocol"),
            (httpx.Response(200, json={"error": {}}), "protocol"),
        ],
    )
    def test_classifies_bad_rpc_responses(
        self, response: httpx.Response, failure: str
    ) -> None:
        pool = SvmRpcPool(
            ["https://a.test"],
            network_id=DEVNET,
            transport=httpx.MockTransport(lambda _request: response),
        )
        with pytest.raises(SvmRpcError) as raised:
            pool.read_balance(
                genesis_hash=DEVNET_GENESIS,
                mint=MINT,
                owner=PAYER,
                decimals=6,
                now_epoch_ms=NOW,
            )
        assert raised.value.failure == failure

    def test_a_malformed_genesis_hash_is_typed(self) -> None:
        pool = SvmRpcPool(
            ["https://a.test"], network_id=DEVNET, transport=rpc({"getGenesisHash": 42})
        )
        with pytest.raises(SvmRpcError) as raised:
            pool.read_balance(
                genesis_hash=DEVNET_GENESIS,
                mint=MINT,
                owner=PAYER,
                decimals=6,
                now_epoch_ms=NOW,
            )
        assert raised.value.failure == "genesis-hash-unreadable"

    def test_an_empty_pool_and_a_wrong_transport_kind_are_refused(self) -> None:
        with pytest.raises(SvmRpcError, match="No RPC endpoint"):
            SvmRpcPool([], network_id=DEVNET).read_balance(
                genesis_hash=DEVNET_GENESIS,
                mint=MINT,
                owner=PAYER,
                decimals=6,
                now_epoch_ms=NOW,
            )
        with pytest.raises(TypeError, match="BaseTransport"):
            SvmRpcPool(
                ["https://a.test"],
                network_id=DEVNET,
                transport=httpx.AsyncHTTPTransport(),
            ).read_balance(
                genesis_hash=DEVNET_GENESIS,
                mint=MINT,
                owner=PAYER,
                decimals=6,
                now_epoch_ms=NOW,
            )

    def test_at_most_two_providers_are_consulted(self) -> None:
        """SPEC §6.4 step 15 caps providers per network at two."""
        pool = SvmRpcPool(
            ["https://a.test", "https://b.test", "https://c.test"],
            network_id=DEVNET,
            transport=rpc({"getGenesisHash": "wrong"}),
        )
        with pytest.raises(SvmRpcError):
            pool.read_balance(
                genesis_hash=DEVNET_GENESIS,
                mint=MINT,
                owner=PAYER,
                decimals=6,
                now_epoch_ms=NOW,
            )
        assert len(pool._endpoints) == 2

    def test_reset_health_forgets_only_this_pools_endpoints(self) -> None:
        health = HealthIndex()
        health.record_failure(HealthIndex.endpoint_id(DEVNET, "a.test"), NOW)
        health.record_failure(HealthIndex.endpoint_id("eip155:8453", "other.test"), NOW)
        SvmRpcPool(["https://a.test"], network_id=DEVNET, health=health).reset_health()
        assert health.size == 1

    def test_reads_a_blockhash_after_proving_the_cluster(self) -> None:
        pool = SvmRpcPool(
            ["https://a.test"],
            network_id=DEVNET,
            transport=rpc({"getLatestBlockhash": {"value": {"blockhash": BLOCKHASH}}}),
        )
        assert pool.latest_blockhash(genesis_hash=DEVNET_GENESIS, now_epoch_ms=NOW) == (
            BLOCKHASH
        )

    def test_a_blockhash_response_without_one_is_typed(self) -> None:
        pool = SvmRpcPool(
            ["https://a.test"],
            network_id=DEVNET,
            transport=rpc({"getLatestBlockhash": {"value": {}}}),
        )
        with pytest.raises(SvmRpcError) as raised:
            pool.latest_blockhash(genesis_hash=DEVNET_GENESIS, now_epoch_ms=NOW)
        assert raised.value.failure == "protocol"


class TestAsyncRpcPool:
    @pytest.mark.asyncio
    async def test_async_reads_match_the_sync_path(self) -> None:
        pool = SvmRpcPool(
            ["https://a.test"],
            network_id=DEVNET,
            transport=rpc(
                {
                    "getAccountInfo": token_account_response(),
                    "getLatestBlockhash": {"value": {"blockhash": BLOCKHASH}},
                }
            ),
        )
        reading = await pool.read_balance_async(
            genesis_hash=DEVNET_GENESIS,
            mint=MINT,
            owner=PAYER,
            decimals=6,
            now_epoch_ms=NOW,
        )
        assert reading.balance_atomic == 5_000_000
        assert (
            await pool.latest_blockhash_async(genesis_hash=DEVNET_GENESIS, now_epoch_ms=NOW)
            == BLOCKHASH
        )

    @pytest.mark.asyncio
    async def test_async_guards_the_transport_kind_and_empty_pool(self) -> None:
        with pytest.raises(SvmRpcError, match="No RPC endpoint"):
            await SvmRpcPool([], network_id=DEVNET).read_balance_async(
                genesis_hash=DEVNET_GENESIS,
                mint=MINT,
                owner=PAYER,
                decimals=6,
                now_epoch_ms=NOW,
            )
        with pytest.raises(TypeError, match="AsyncBaseTransport"):
            await SvmRpcPool(
                ["https://a.test"], network_id=DEVNET, transport=httpx.HTTPTransport()
            ).latest_blockhash_async(genesis_hash=DEVNET_GENESIS, now_epoch_ms=NOW)

    @pytest.mark.asyncio
    async def test_async_fails_over_on_a_wrong_cluster(self) -> None:
        pool = SvmRpcPool(
            ["https://a.test", "https://b.test"],
            network_id=DEVNET,
            transport=rpc(
                {
                    "a.test:getGenesisHash": "wrong",
                    "getAccountInfo": token_account_response(),
                }
            ),
        )
        reading = await pool.read_balance_async(
            genesis_hash=DEVNET_GENESIS,
            mint=MINT,
            owner=PAYER,
            decimals=6,
            now_epoch_ms=NOW,
        )
        assert reading.endpoint == "b.test"
