"""Key hierarchy, sealing, and operator-facing verification phrases.

All long-lived secret material in canaryEW descends from a single operator
passphrase through Argon2id and HKDF. Nothing in this module ever touches an
xpub or a descriptor -- see ``enroll.py`` for why those are never persisted.
"""

from __future__ import annotations

import hmac
import os
import secrets as _stdlib_secrets
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Argon2id parameters. Deliberately expensive: this KDF runs at most a handful of
# times per boot, never in the poll loop, so operator-perceptible cost is fine and
# offline attack cost is what we are buying.
ARGON2_MEMORY_KIB: Final[int] = 256 * 1024  # 256 MiB
ARGON2_TIME_COST: Final[int] = 3
ARGON2_PARALLELISM: Final[int] = 4
KEK_LEN: Final[int] = 32
SALT_LEN: Final[int] = 16

_INFO_STATE: Final[bytes] = b"canaryew/v1/state-encryption"
_INFO_HMAC: Final[bytes] = b"canaryew/v1/alert-authentication"
_INFO_PHRASE: Final[bytes] = b"canaryew/v1/verification-phrase"

VERIFICATION_WORD_COUNT: Final[int] = 4

# A compact, deliberately unambiguous wordlist. 256 entries -> 8 bits per word,
# so a 4-word phrase carries 32 bits. This is an anti-spoofing token read by a
# human under stress, not key material; 32 bits is ample and the words are chosen
# to be short, phonetically distinct, and free of homophones.
_WORDLIST: Final[tuple[str, ...]] = tuple(
    """
    amber anchor anvil apex arbor arrow ashen aspen atlas aurora avalon
    axiom baker balsam banner barley basalt beacon bellow birch bishop bison
    blaze bluff bolder bonfire border bramble brass bridge bronze burrow
    cactus canyon carbon cargo cavern cedar cinder cipher citrus clover
    cobalt comet copper coral cortex cosmos cougar crater crimson crystal
    cypress dagger dahlia damson dapple dawn delta denim desert diamond
    dingo dolmen domino dover dragon dunes ebony echo ember emblem engine
    ensign epoch equinox ermine ether falcon fathom fennel ferrous fiddle
    filbert finch fjord flint florin forge fossil fresco fulcrum furnace
    gadget gallant gambit garnet gazelle gecko geode geyser ginger glacier
    gneiss gopher granite gravel grotto gryphon gusto hallow hamlet harbor
    harvest hazel heather helix hemlock heron hollow hornet hurdle indigo
    inkwell iodine island ivory jasper jetty jonquil jubilee juniper kestrel
    kindle kiosk kismet kite lagoon lantern lapis larch lattice lavender
    ledger legend lichen lilac linden lintel lupine lyric magnet mahogany
    mallow mammoth mandrake mangrove maple marble mariner marlin marrow
    meadow mercury meridian mesa mica midland mineral minnow mistral mohair
    monarch moraine mortar mulberry mustang nautilus nebula nectar needle
    nickel nimbus nomad nutmeg oakum obsidian ocher octave olive onyx opal
    orchard oriole osprey otter outpost oxbow paddock palisade pampas
    papyrus parsley pastel peatland pebble pelican pennant peridot petrel
    pewter pigment pillar pincer pinnacle pioneer piston plateau plover
    plumage polaris pollen poplar portage potash prairie primrose prism
    pueblo pumice quarry quartz quiver radish rampart rapids raven redwood
    reef regent relic rhubarb ridge rigging rivet roebuck rosewood rowan
    rudder russet saffron sage salt sandbar sapphire sardine
    """.split()
)


class SecretsError(RuntimeError):
    """Raised when key derivation, sealing, or unsealing fails."""


@dataclass(frozen=True)
class KeyMaterial:
    """Derived key hierarchy for one operator passphrase.

    Held in memory only. Python cannot reliably zero immutable ``bytes``; callers
    that need best-effort scrubbing should use :func:`wipe` on ``bytearray``
    copies and treat this dataclass as unscrubbable. This limitation is
    documented rather than hidden -- see ``docs/THREAT-MODEL.md``.
    """

    state_key: bytes
    """32-byte ChaCha20-Poly1305 key protecting the state store."""

    hmac_key: bytes
    """32-byte key authenticating heartbeats and alerts."""

    verification_phrase: str
    """Operator-memorized words echoed in every genuine notification."""

    def fingerprint(self) -> str:
        """Short non-reversible identifier, safe to log and display."""
        digest = sha256(b"canaryew/fingerprint" + self.hmac_key).hexdigest()
        return digest[:12]


def new_salt() -> bytes:
    """Generate a fresh Argon2id salt."""
    return os.urandom(SALT_LEN)


def derive_kek(passphrase: str, salt: bytes) -> bytes:
    """Stretch the operator passphrase into a 32-byte key-encryption key."""
    if not passphrase:
        raise SecretsError("Passphrase must not be empty.")
    if len(salt) != SALT_LEN:
        raise SecretsError(f"Salt must be {SALT_LEN} bytes, got {len(salt)}.")

    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEK_LEN,
        type=Argon2Type.ID,
    )


def _hkdf(kek: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(kek)


def derive_keys(kek: bytes) -> KeyMaterial:
    """Expand a KEK into the full key hierarchy."""
    if len(kek) != KEK_LEN:
        raise SecretsError(f"KEK must be {KEK_LEN} bytes, got {len(kek)}.")

    state_key = _hkdf(kek, _INFO_STATE)
    hmac_key = _hkdf(kek, _INFO_HMAC)
    phrase_seed = _hkdf(kek, _INFO_PHRASE, length=VERIFICATION_WORD_COUNT)

    words = [_WORDLIST[byte % len(_WORDLIST)] for byte in phrase_seed]
    return KeyMaterial(
        state_key=state_key,
        hmac_key=hmac_key,
        verification_phrase=" ".join(words),
    )


def unlock(passphrase: str, salt: bytes) -> KeyMaterial:
    """Convenience wrapper: passphrase + salt -> full key hierarchy."""
    return derive_keys(derive_kek(passphrase, salt))


# --------------------------------------------------------------------------- #
# Authenticated encryption for the state store
# --------------------------------------------------------------------------- #


def seal(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt with ChaCha20-Poly1305. Output is ``nonce || ciphertext``."""
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    return nonce + aead.encrypt(nonce, plaintext, associated_data)


def unseal(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    """Reverse :func:`seal`. Raises :class:`SecretsError` on tamper or wrong key."""
    if len(blob) < 12:
        raise SecretsError("Sealed blob is truncated.")
    nonce, ciphertext = blob[:12], blob[12:]
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, associated_data)
    except Exception as exc:  # cryptography raises InvalidTag
        raise SecretsError(
            "Unable to decrypt state: wrong passphrase, or the store was tampered with."
        ) from exc


# --------------------------------------------------------------------------- #
# Message authentication for heartbeats and alerts
# --------------------------------------------------------------------------- #


def mac(key: bytes, *parts: bytes) -> str:
    """Compute a hex HMAC-SHA256 over length-prefixed parts.

    Parts are length-prefixed so that ``mac(k, b"ab", b"c")`` and
    ``mac(k, b"a", b"bc")`` differ -- naive concatenation would collide.
    """
    engine = hmac.new(key, digestmod=sha256)
    for part in parts:
        engine.update(len(part).to_bytes(4, "big"))
        engine.update(part)
    return engine.hexdigest()


def verify_mac(key: bytes, candidate: str, *parts: bytes) -> bool:
    """Constant-time verification of a hex MAC produced by :func:`mac`."""
    return hmac.compare_digest(candidate, mac(key, *parts))


def wipe(buffer: bytearray) -> None:
    """Best-effort zeroization of a mutable buffer.

    Only meaningful for ``bytearray``. Python offers no guarantee that copies
    were not made by the interpreter or the allocator; this reduces the window,
    it does not close it.
    """
    for index in range(len(buffer)):
        buffer[index] = 0


def constant_time_token(length: int = 32) -> str:
    """Generate a URL-safe random token (session ids, webhook nonces)."""
    return _stdlib_secrets.token_urlsafe(length)
