import base64
import pathlib
import subprocess
import tempfile

from agentic_memory_fabric.crypto import canonicalize_event_for_signing
from agentic_memory_fabric.events import EventEnvelope


def _b64url_no_pad(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sign_event_ed25519(event: EventEnvelope) -> tuple[str, dict[str, str]]:
    """Return base64 signature and public JWK for canonical event bytes."""
    message = canonicalize_event_for_signing(event)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = pathlib.Path(tmpdir)
        secret_key_path = tmp / "sk.pem"
        public_key_path = tmp / "pk.pem"
        message_path = tmp / "msg.bin"
        signature_path = tmp / "sig.bin"

        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(secret_key_path)],
            check=True,
            capture_output=True,
            text=False,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(secret_key_path), "-pubout", "-out", str(public_key_path)],
            check=True,
            capture_output=True,
            text=False,
        )
        message_path.write_bytes(message)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(secret_key_path),
                "-rawin",
                "-in",
                str(message_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            capture_output=True,
            text=False,
        )
        signature = base64.b64encode(signature_path.read_bytes()).decode("ascii")
        pub_der = subprocess.check_output(
            ["openssl", "pkey", "-pubin", "-in", str(public_key_path), "-outform", "DER"]
        )
    pub_raw = pub_der[-32:]
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url_no_pad(pub_raw)}
    return signature, jwk
