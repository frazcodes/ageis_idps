"""Client-side hardware fingerprinting, license verification, and activation service.

Enforces:
1. Unique Hardware ID (HWID) binding based on Motherboard/BIOS UUID.
2. Local license persistence in encrypted/hashed token format.
3. Online validation against the Aegis Cloud License Portal / Firebase API.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from aegis_shared.logging import get_logger

logger = get_logger(__name__)

# Default license server URL (can be overridden via AEGIS_LICENSE_SERVER_URL)
DEFAULT_LICENSE_SERVER = os.environ.get(
    "AEGIS_LICENSE_SERVER_URL",
    "http://localhost:3000"
)

LICENSE_STORAGE_DIR = Path.home() / ".aegis"
LICENSE_STORAGE_FILE = LICENSE_STORAGE_DIR / "license.json"


@dataclass(frozen=True)
class LocalLicense:
    """Active local license metadata on this endpoint."""

    key: str
    client_name: str
    organization: str
    expires_at: str
    hardware_id: str
    activated_at: str
    token_hash: str

    @property
    def is_expired(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            return exp.timestamp() <= datetime.now(UTC).timestamp()
        except Exception:
            return True


def get_hardware_fingerprint() -> str:
    """Generate a stable, unique Hardware ID (HWID) for this computer."""
    raw_id = ""

    if sys.platform == "win32":
        # Method 1: Windows Registry MachineGuid (100% reliable, zero process spawn)
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography"
            ) as key:
                raw_id, _ = winreg.QueryValueEx(key, "MachineGuid")
        except Exception:
            pass

        # Method 2: Fallback to Motherboard BIOS UUID
        if not raw_id:
            try:
                cmd = ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if res.returncode == 0 and res.stdout.strip():
                    raw_id = res.stdout.strip()
            except Exception:
                pass

    if not raw_id:
        # Fallback for non-Windows or virtual machines
        raw_id = f"{platform.node()}-{platform.processor()}-{os.name}"

    # Return clean uppercase SHA-256 fingerprint formatted in segments
    digest = hashlib.sha256(raw_id.strip().encode("utf-8")).hexdigest().upper()
    return f"{digest[:8]}-{digest[8:16]}-{digest[16:24]}-{digest[24:32]}"


class LicenseClient:
    """Coordinates local license validation and remote cloud activation."""

    def __init__(self, server_url: str | None = None) -> None:
        self.server_url = (server_url or DEFAULT_LICENSE_SERVER).rstrip("/")
        self.hardware_id = get_hardware_fingerprint()
        self.hostname = platform.node()

    def load_local_license(self) -> LocalLicense | None:
        """Load locally cached license if valid and untampered."""
        if not LICENSE_STORAGE_FILE.exists():
            return None

        try:
            data = json.loads(LICENSE_STORAGE_FILE.read_text(encoding="utf-8"))
            key = data.get("key", "")
            hwid = data.get("hardware_id", "")
            token_hash = data.get("token_hash", "")

            # Verify integrity
            expected_hash = hashlib.sha256(f"{key}:{hwid}:{self.hardware_id}".encode()).hexdigest()
            if token_hash != expected_hash:
                logger.warning("License token integrity check failed (hardware mismatch)")
                return None

            lic = LocalLicense(
                key=key,
                client_name=data.get("client_name", "Registered User"),
                organization=data.get("organization", "Aegis Client"),
                expires_at=data.get("expires_at", ""),
                hardware_id=hwid,
                activated_at=data.get("activated_at", ""),
                token_hash=token_hash,
            )

            if lic.is_expired:
                logger.warning("Stored local license is expired")
                return None

            return lic
        except Exception as exc:
            logger.debug("Failed reading local license: %s", exc)
            return None

    def activate_online(self, license_key: str) -> dict[str, Any]:
        """Send activation request to the Cloud License Portal or Firebase directly."""
        clean_key = license_key.strip().upper()

        # Step 1: Direct Firebase Cloud verification (if serviceAccountKey.json is present)
        direct_result = self._verify_directly_with_firebase(clean_key)
        if direct_result is not None:
            if direct_result.get("valid"):
                self._save_local_license(clean_key, direct_result)
                return {"success": True, "data": direct_result}
            else:
                return {"success": False, "message": direct_result.get("message", "License validation failed.")}

        # Step 2: Query Cloud Web Portal API
        url = f"{self.server_url}/api/licenses/verify"
        payload = {
            "licenseKey": clean_key,
            "hardwareId": self.hardware_id,
            "machineHostname": self.hostname,
        }

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "Aegis-IDPS-Client/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))

                if result.get("valid"):
                    # Save local token
                    self._save_local_license(clean_key, result)
                    return {"success": True, "data": result}
                else:
                    return {"success": False, "message": result.get("message", "License is invalid")}

        except urllib.error.HTTPError as err:
            try:
                body = json.loads(err.read().decode("utf-8"))
                return {"success": False, "message": body.get("message", f"HTTP Error {err.code}")}
            except Exception:
                return {"success": False, "message": f"Server error: HTTP {err.code}"}
        except urllib.error.URLError as err:
            # Fallback check: if server is offline and local license exists
            local = self.load_local_license()
            if local and local.key == clean_key and not local.is_expired:
                return {"success": True, "data": {"clientName": local.client_name, "daysRemaining": 30}}
            return {"success": False, "message": f"Could not reach license server ({self.server_url}). Check internet connection."}
        except Exception as exc:
            return {"success": False, "message": f"Activation failed: {exc}"}

    def _verify_directly_with_firebase(self, key: str) -> dict[str, Any] | None:
        """Directly verify against Firebase Firestore if serviceAccountKey.json is available."""
        candidates = [
            Path("license-portal/serviceAccountKey.json"),
            Path.home() / ".aegis" / "serviceAccountKey.json",
        ]
        key_file = next((p for p in candidates if p.exists()), None)
        if not key_file:
            return None

        try:
            import base64
            import time
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

            creds = json.loads(key_file.read_text(encoding="utf-8"))
            now = int(time.time())
            header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
            payload = base64.urlsafe_b64encode(json.dumps({
                "iss": creds["client_email"],
                "scope": "https://www.googleapis.com/auth/datastore",
                "aud": creds["token_uri"],
                "exp": now + 3600,
                "iat": now,
            }).encode()).rstrip(b"=").decode()

            message = f"{header}.{payload}".encode("utf-8")
            pkey = serialization.load_pem_private_key(creds["private_key"].encode("utf-8"), password=None)
            if not isinstance(pkey, RSAPrivateKey):
                logger.error("Loaded private key is not an RSA private key")
                return None
            sig = pkey.sign(message, padding.PKCS1v15(), hashes.SHA256())
            jwt_token = f"{header}.{payload}." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

            # Exchange JWT for Access Token
            token_data = urllib.parse.urlencode({
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt_token,
            }).encode("utf-8")
            token_req = urllib.request.Request(
                creds["token_uri"],
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            with urllib.request.urlopen(token_req, timeout=5) as token_resp:
                token_json = json.loads(token_resp.read().decode())
                access_token = token_json.get("access_token")

            # Fetch license document from Firestore
            f_url = f"https://firestore.googleapis.com/v1/projects/{creds['project_id']}/databases/(default)/documents/licenses/{key}"
            f_req = urllib.request.Request(f_url, headers={"Authorization": f"Bearer {access_token}"})
            with urllib.request.urlopen(f_req, timeout=5) as f_resp:
                doc = json.loads(f_resp.read().decode())
                fields = doc.get("fields", {})
                client_name = fields.get("clientName", {}).get("stringValue", "Aegis User")
                is_active = fields.get("isActive", {}).get("booleanValue", True)
                expires_at = fields.get("expiresAt", {}).get("stringValue", "")
                hwid = fields.get("hardwareId", {}).get("stringValue", None)

                if not is_active:
                    return {"valid": False, "message": "This license key has been revoked by the administrator."}

                # Check expiration
                try:
                    exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    diff = exp_dt.timestamp() - datetime.now(UTC).timestamp()
                    days = max(0, int(diff // 86400))
                    if diff <= 0:
                        return {"valid": False, "message": "This license has expired."}
                except Exception:
                    days = 30

                # Hardware ID check and bind
                if not hwid:
                    patch_url = f"{f_url}?updateMask.fieldPaths=hardwareId&updateMask.fieldPaths=machineHostname&updateMask.fieldPaths=activatedAt"
                    patch_body = {
                        "fields": {
                            "hardwareId": {"stringValue": self.hardware_id},
                            "machineHostname": {"stringValue": self.hostname},
                            "activatedAt": {"stringValue": datetime.now(UTC).isoformat()},
                        }
                    }
                    patch_req = urllib.request.Request(
                        patch_url,
                        data=json.dumps(patch_body).encode("utf-8"),
                        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                        method="PATCH",
                    )
                    try:
                        urllib.request.urlopen(patch_req, timeout=5)
                    except Exception as patch_err:
                        logger.debug("Failed binding HWID in Firestore: %s", patch_err)
                elif hwid.upper() != self.hardware_id.upper():
                    return {"valid": False, "message": "License key is locked to another computer."}

                return {
                    "valid": True,
                    "clientName": client_name,
                    "organization": fields.get("organization", {}).get("stringValue", "Default Org"),
                    "expiresAt": expires_at,
                    "daysRemaining": days,
                }
        except urllib.error.HTTPError as http_err:
            if http_err.code == 404:
                return {"valid": False, "message": "License key not found in Firebase database."}
            return None
        except Exception as exc:
            logger.debug("Direct Firebase verification error: %s", exc)
            return None

    def _save_local_license(self, key: str, verify_result: dict[str, Any]) -> None:
        """Persist verified license locally."""
        try:
            LICENSE_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
            token_hash = hashlib.sha256(f"{key}:{self.hardware_id}:{self.hardware_id}".encode()).hexdigest()
            record = {
                "key": key,
                "client_name": verify_result.get("clientName", "Aegis Client"),
                "organization": verify_result.get("organization", "Default Org"),
                "expires_at": verify_result.get("expiresAt", datetime.now(UTC).isoformat()),
                "hardware_id": self.hardware_id,
                "activated_at": datetime.now(UTC).isoformat(),
                "token_hash": token_hash,
            }
            LICENSE_STORAGE_FILE.write_text(json.dumps(record, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed saving local license file: %s", exc)

