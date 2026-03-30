"""
注册流程引擎
从 main.py 中提取并重构的注册流程
加入了 123.py 的模拟浏览器并发注册流程
"""

import re
import json
import time
import logging
import secrets
import string
import random
import uuid
import hashlib
import base64
from typing import Optional, Dict, Any, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode

from curl_cffi import requests as cffi_requests
from curl_cffi.requests.models import Response

from .openai.oauth import OAuthManager, OAuthStart
from .http_client import OpenAIHTTPClient, HTTPClientError
from ..services import EmailServiceFactory, BaseEmailService, EmailServiceType
from ..database import crud
from ..database.session import get_db
from ..config.constants import (
    OPENAI_API_ENDPOINTS,
    generate_random_user_info,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_CHARSET,
    AccountStatus,
    TaskStatus,
)
from ..config.settings import get_settings

logger = logging.getLogger(__name__)

# ================= Chrome Fingerprints =================
_CHROME_PROFILES = [
    {
        "major": 131, "impersonate": "chrome131",
        "build": 6778, "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 133, "impersonate": "chrome133a",
        "build": 6943, "patch_range": (33, 153),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
    {
        "major": 136, "impersonate": "chrome136",
        "build": 7103, "patch_range": (48, 175),
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
]

def _random_chrome_version():
    profile = random.choice(_CHROME_PROFILES)
    major = profile["major"]
    build = profile["build"]
    patch = random.randint(*profile["patch_range"])
    full_ver = f"{major}.0.{build}.{patch}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
    return profile["impersonate"], major, full_ver, ua, profile["sec_ch_ua"]


def _random_delay(low=0.3, high=1.0):
    time.sleep(random.uniform(low, high))


def _make_trace_headers():
    trace_id = random.randint(10**17, 10**18 - 1)
    parent_id = random.randint(10**17, 10**18 - 1)
    tp = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
    return {
        "traceparent": tp, "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum", "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": str(trace_id), "x-datadog-parent-id": str(parent_id),
    }


def _generate_pkce():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge

def _extract_code_from_url(url: str):
    if not url or "code=" not in url:
        return None
    try:
        return parse_qs(urlparse(url).query).get("code", [None])[0]
    except Exception:
        return None

# ================= SentinelTokenGenerator =================
class SentinelTokenGenerator:
    """纯 Python 版本 sentinel token 生成器（PoW）"""
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id=None, user_agent=None):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent or "Mozilla/5.0"
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str):
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        h &= 0xFFFFFFFF
        return format(h, "08x")

    def _get_config(self):
        now_str = time.strftime(
            "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)",
            time.gmtime(),
        )
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        nav_prop = random.choice([
            "vendorSub", "productSub", "vendor", "maxTouchPoints",
            "scheduling", "userActivation", "doNotTrack", "geolocation",
            "connection", "plugins", "mimeTypes", "pdfViewerEnabled",
            "webkitTemporaryStorage", "webkitPersistentStorage",
            "hardwareConcurrency", "cookieEnabled", "credentials",
            "mediaDevices", "permissions", "locks", "ink",
        ])
        nav_val = f"{nav_prop}-undefined"

        return [
            "1920x1080", now_str, 4294705152, random.random(), self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js", None, None,
            "en-US", "en-US,en", random.random(), nav_val,
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now, self.sid, "", random.choice([4, 8, 12, 16]), time_origin,
        ]

    @staticmethod
    def _base64_encode(data):
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        diff_len = len(difficulty)
        if hash_hex[:diff_len] <= difficulty:
            return data + "~S"
        return None

    def generate_token(self, seed=None, difficulty=None):
        seed = seed if seed is not None else self.requirements_seed
        difficulty = str(difficulty or "0")
        start_time = time.time()
        config = self._get_config()

        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start_time, seed, difficulty, config, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self):
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        data = self._base64_encode(config)
        return "gAAAAAC" + data


def fetch_sentinel_challenge(session, device_id, flow="authorize_continue", user_agent=None, sec_ch_ua=None, impersonate=None):
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    req_body = {
        "p": generator.generate_requirements_token(),
        "id": device_id,
        "flow": flow,
    }
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or "Mozilla/5.0",
        "sec-ch-ua": sec_ch_ua or '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    kwargs = {"data": json.dumps(req_body), "headers": headers, "timeout": 20}
    if impersonate:
        kwargs["impersonate"] = impersonate

    try:
        resp = session.post("https://sentinel.openai.com/backend-api/sentinel/req", **kwargs)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None

def build_sentinel_token(session, device_id, flow="authorize_continue", user_agent=None, sec_ch_ua=None, impersonate=None):
    challenge = fetch_sentinel_challenge(session, device_id, flow=flow, user_agent=user_agent, sec_ch_ua=sec_ch_ua, impersonate=impersonate)
    if not challenge: return None
    c_value = challenge.get("token", "")
    if not c_value: return None
    pow_data = challenge.get("proofofwork") or {}
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(seed=pow_data.get("seed"), difficulty=pow_data.get("difficulty", "0"))
    else:
        p_value = generator.generate_requirements_token()
    return json.dumps({"p": p_value, "t": "", "c": c_value, "id": device_id, "flow": flow}, separators=(",", ":"))


# ================= Core Registration Classes =================

@dataclass
class RegistrationResult:
    success: bool
    email: str = ""
    password: str = ""
    account_id: str = ""
    workspace_id: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    session_token: str = ""
    error_message: str = ""
    logs: list = None
    metadata: dict = None
    source: str = "register"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "email": self.email,
            "password": self.password,
            "account_id": self.account_id,
            "workspace_id": self.workspace_id,
            "access_token": self.access_token[:20] + "..." if self.access_token else "",
            "refresh_token": self.refresh_token[:20] + "..." if self.refresh_token else "",
            "id_token": self.id_token[:20] + "..." if self.id_token else "",
            "session_token": self.session_token[:20] + "..." if self.session_token else "",
            "error_message": self.error_message,
            "logs": self.logs or [],
            "metadata": self.metadata or {},
            "source": self.source,
        }

class RegistrationEngine:
    def __init__(self, email_service: BaseEmailService, proxy_url: Optional[str] = None, callback_logger: Optional[Callable[[str], None]] = None, task_uuid: Optional[str] = None):
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid

        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()
        self.session = cffi_requests.Session(impersonate=self.impersonate)
        if proxy_url:
            self.session.proxies = {"http": proxy_url, "https": proxy_url}
        
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": self.sec_ch_ua, "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"', "sec-ch-ua-arch": '"x86"', "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
        })
        
        self.device_id = str(uuid.uuid4())
        self.session.cookies.set("oai-did", self.device_id, domain="chatgpt.com")
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        self.auth_session_logging_id = str(uuid.uuid4())

        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.email_info: Optional[Dict[str, Any]] = None
        self.session_token: Optional[str] = None
        self.logs: list = []
        self._otp_sent_at: Optional[float] = None
        self._callback_url = None
        self._final_callback_url = None

        self.BASE = "https://chatgpt.com"
        self.AUTH = "https://auth.openai.com"

        settings = get_settings()
        self.oauth_client_id = settings.openai_client_id
        self.oauth_redirect_uri = settings.openai_redirect_uri
        self.oauth_issuer = settings.openai_auth_url.split('/oauth/')[0] if settings.openai_auth_url else "https://auth.openai.com"

    def _log(self, message: str, level: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        self.logs.append(log_message)
        if self.callback_logger:
            self.callback_logger(log_message)
        if self.task_uuid:
            try:
                with get_db() as db:
                    crud.append_task_log(db, self.task_uuid, log_message)
            except Exception as e:
                logger.warning(f"记录任务日志失败: {e}")
        if level == "error": logger.error(message)
        elif level == "warning": logger.warning(message)
        else: logger.info(message)

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        return ''.join(secrets.choice(PASSWORD_CHARSET) for _ in range(length))

    def _create_email(self) -> bool:
        try:
            self.email_info = self.email_service.create_email()
            if not self.email_info or "email" not in self.email_info:
                return False
            self.email = self.email_info["email"]
            return True
        except Exception as e:
            self._log(f"创建邮箱失败: {e}", "error")
            return False

    def wait_for_verification_email(self, timeout=120):
        self._log("等待验证码邮件...")
        email_id = self.email_info.get("service_id") if self.email_info else None
        code = self.email_service.get_verification_code(
            email=self.email,
            email_id=email_id,
            timeout=timeout,
            pattern=OTP_CODE_PATTERN,
            otp_sent_at=self._otp_sent_at,
        )
        return code

    # ======== HTTP Flows ========

    def visit_homepage(self):
        url = f"{self.BASE}/"
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
        self._log(f"Visit homepage -> {r.status_code}")

    def get_csrf(self) -> str:
        url = f"{self.BASE}/api/auth/csrf"
        r = self.session.get(url, headers={"Accept": "application/json", "Referer": f"{self.BASE}/"})
        data = r.json()
        token = data.get("csrfToken", "")
        self._log(f"Get CSRF -> {r.status_code}")
        if not token: raise Exception("Failed to get CSRF token")
        return token

    def signin(self, email: str, csrf: str) -> str:
        url = f"{self.BASE}/api/auth/signin/openai"
        params = {
            "prompt": "login", "ext-oai-did": self.device_id,
            "auth_session_logging_id": self.auth_session_logging_id,
            "screen_hint": "login_or_signup", "login_hint": email,
        }
        form_data = {"callbackUrl": f"{self.BASE}/", "csrfToken": csrf, "json": "true"}
        r = self.session.post(url, params=params, data=form_data, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json", "Referer": f"{self.BASE}/", "Origin": self.BASE,
        })
        data = r.json()
        authorize_url = data.get("url", "")
        self._log(f"Signin -> {r.status_code}")
        if not authorize_url: raise Exception("Failed to get authorize URL")
        return authorize_url

    def authorize(self, url: str) -> str:
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{self.BASE}/", "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
        final_url = str(r.url)
        self._log(f"Authorize -> {r.status_code}")
        return final_url

    def _fetch_sentinel_tokens(self):
        sentinel_token = build_sentinel_token(
            self.session, self.device_id, flow="authorize_continue",
            user_agent=self.ua, sec_ch_ua=self.sec_ch_ua, impersonate=self.impersonate,
        )
        so_token = build_sentinel_token(
            self.session, self.device_id, flow="oauth_create_account",
            user_agent=self.ua, sec_ch_ua=self.sec_ch_ua, impersonate=self.impersonate,
        )
        return sentinel_token, so_token

    def register(self, email: str, password: str, sentinel_token: str = None):
        url = f"{self.AUTH}/api/accounts/user/register"
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Referer": f"{self.AUTH}/create-account/password", "Origin": self.AUTH}
        headers.update(_make_trace_headers())
        if sentinel_token: headers["openai-sentinel-token"] = sentinel_token
        r = self.session.post(url, json={"username": email, "password": password}, headers=headers)
        try: data = r.json()
        except: data = {"text": r.text[:500]}
        self._log(f"Register -> {r.status_code}")
        return r.status_code, data

    def send_otp(self):
        self._otp_sent_at = time.time()
        url = f"{self.AUTH}/api/accounts/email-otp/send"
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{self.AUTH}/create-account/password", "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
        self._log(f"Send OTP -> {r.status_code}")
        return r.status_code, {}

    def validate_otp(self, code: str, sentinel_token: str = None):
        url = f"{self.AUTH}/api/accounts/email-otp/validate"
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Referer": f"{self.AUTH}/email-verification", "Origin": self.AUTH}
        headers.update(_make_trace_headers())
        if sentinel_token: headers["openai-sentinel-token"] = sentinel_token
        r = self.session.post(url, json={"code": code}, headers=headers)
        try: data = r.json()
        except: data = {"text": r.text[:500]}
        self._log(f"Validate OTP -> {r.status_code}")
        return r.status_code, data

    def create_account(self, name: str, birthdate: str, so_token: str = None):
        url = f"{self.AUTH}/api/accounts/create_account"
        headers = {
            "Content-Type": "application/json", "Accept": "application/json",
            "Referer": f"{self.AUTH}/about-you", "Origin": self.AUTH,
            "User-Agent": self.ua, "oai-device-id": self.device_id,
            "sec-ch-ua": self.sec_ch_ua, "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"', "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors", "sec-fetch-site": "same-origin",
        }
        headers.update(_make_trace_headers())
        payload = {"name": name, "birthdate": birthdate}
        if so_token: headers["openai-sentinel-token"] = so_token

        r = self.session.post(url, json=payload, headers=headers, impersonate=self.impersonate)
        if r.status_code == 400 and "registration_disallowed" in (r.text or ""):
            self._log("registration_disallowed, 重新获取 sentinel 重试...")
            fresh_token = build_sentinel_token(
                self.session, self.device_id, flow="oauth_create_account",
                user_agent=self.ua, sec_ch_ua=self.sec_ch_ua, impersonate=self.impersonate,
            )
            if fresh_token:
                headers["openai-sentinel-token"] = fresh_token
                r = self.session.post(url, json=payload, headers=headers, impersonate=self.impersonate)

        try: data = r.json()
        except: data = {"text": r.text[:500]}
        if isinstance(data, dict):
            cb = data.get("continue_url") or data.get("url") or data.get("redirect_url")
            if cb: self._callback_url = cb
        self._log(f"Create Account -> {r.status_code}")
        return r.status_code, data

    def callback(self, url: str = None):
        if not url: url = self._callback_url
        if not url:
            self._log("No callback URL")
            return None, None
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
        self._final_callback_url = str(r.url)
        self._log(f"Callback -> {r.status_code}")
        return r.status_code, {"final_url": self._final_callback_url}

    @staticmethod
    def _find_jwt_in_data(data, depth=0):
        if depth > 5: return None
        if isinstance(data, str):
            parts = data.split(".")
            if len(parts) == 3 and len(data) > 100:
                try:
                    payload = parts[1]; padding = 4 - len(payload) % 4
                    if padding != 4: payload += "=" * padding
                    decoded = base64.urlsafe_b64decode(payload)
                    obj = json.loads(decoded)
                    if isinstance(obj, dict) and ("exp" in obj or "iat" in obj or "sub" in obj):
                        return data
                except: pass
            return None
        if isinstance(data, dict):
            for v in data.values():
                res = RegistrationEngine._find_jwt_in_data(v, depth + 1)
                if res: return res
        if isinstance(data, list):
            for item in data:
                res = RegistrationEngine._find_jwt_in_data(item, depth + 1)
                if res: return res
        return None

    def get_chatgpt_session_tokens(self):
        try:
            referer = self._final_callback_url or f"{self.BASE}/"
            r = self.session.get(f"{self.BASE}/api/auth/session", headers={
                "Accept": "application/json", "Referer": referer, "User-Agent": self.ua,
            }, timeout=30, impersonate=self.impersonate)
            if r.status_code != 200: return None
            data = r.json()
            access_token = data.get("accessToken") or data.get("access_token") or ""
            if not access_token: access_token = self._find_jwt_in_data(data)
            if not access_token: return None
            return {
                "access_token": access_token,
                "refresh_token": data.get("refreshToken") or data.get("refresh_token") or "",
                "id_token": data.get("idToken") or data.get("id_token") or "",
            }
        except: return None

    # ====== Main Run ======

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)

        try:
            self._log("=" * 60)
            self._log("开始注册流程 (模拟浏览器方式)")
            self._log("=" * 60)

            if not self._create_email():
                result.error_message = "创建邮箱失败"
                return result
            result.email = self.email
            self.password = self._generate_password()
            result.password = self.password
            
            user_info = generate_random_user_info()
            name = user_info['name']
            birthdate = user_info['birthdate']

            self._log("访问 ChatGPT 首页...")
            self.visit_homepage()
            _random_delay(0.3, 0.8)

            self._log("获取 CSRF, 执行 Signin...")
            csrf = self.get_csrf()
            _random_delay(0.2, 0.5)
            auth_url = self.signin(self.email, csrf)
            _random_delay(0.3, 0.8)

            self._log("Authorize跳转...")
            final_url = self.authorize(auth_url)
            final_path = urlparse(final_url).path
            self._log(f"授权路径 -> {final_path}")
            
            _random_delay(0.3, 0.8)

            self._log("获取 Sentinel Token...")
            sentinel_token, so_token = self._fetch_sentinel_tokens()

            need_otp = False
            
            if "create-account/password" in final_path:
                self._log("全新注册流程: 提交密码")
                _random_delay(0.5, 1.0)
                status, data = self.register(self.email, self.password, sentinel_token)
                if status != 200: raise Exception(f"Register 失败 ({status}): {data}")
                _random_delay(0.3, 0.8)
                self.send_otp()
                need_otp = True
            elif "email-verification" in final_path or "email-otp" in final_path:
                self._log("遇到已注册/二次验证 OTP，等待验证码")
                need_otp = True
            elif "about-you" in final_path:
                self._log("跳到 about-you")
                _random_delay(0.5, 1.0)
                self.create_account(name, birthdate, so_token)
                self.callback()
            elif "callback" in final_path or "chatgpt.com" in final_url:
                self._log("跳过注册，直接回调")
            else:
                self._log(f"未知跳转路径: {final_url}，默认走新注册")
                self.register(self.email, self.password, sentinel_token)
                self.send_otp()
                need_otp = True

            if need_otp:
                otp_code = self.wait_for_verification_email(timeout=120)
                if not otp_code: raise Exception("获取验证码超时或失败")
                self._log(f"拿到验证码: {otp_code}")
                _random_delay(0.3, 0.8)
                status, data = self.validate_otp(otp_code, sentinel_token)
                if status != 200:
                    self._log("验证码通过失败，重试发送...")
                    self.send_otp()
                    _random_delay(1.0, 2.0)
                    otp_code = self.wait_for_verification_email(timeout=60)
                    if not otp_code: raise Exception("重试验证码失败")
                    status, data = self.validate_otp(otp_code, sentinel_token)
                    if status != 200: raise Exception("OTP验证反复失败")

            # 继续流程
            continue_url = ""
            if 'data' in locals() and isinstance(data, dict):
                continue_url = data.get("continue_url", "")
            if not continue_url: continue_url = f"{self.AUTH}/about-you"
            if continue_url.startswith("/"): continue_url = f"{self.AUTH}{continue_url}"

            _random_delay(0.5, 1.0)
            try:
                self.session.get(continue_url, headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": f"{self.AUTH}/email-verification", "Upgrade-Insecure-Requests": "1",
                }, allow_redirects=True, impersonate=self.impersonate)
            except Exception as e:
                self._log(f"访问 about-you 可能由于回调重定向断开: {e}")

            _random_delay(0.5, 1.5)
            status, data = self.create_account(name, birthdate, so_token)
            
            _random_delay(0.2, 0.5)
            self.callback()

            # 抓取 Token
            self._log("尝试从 ChatGPT Session 提取 Token")
            tokens = self.get_chatgpt_session_tokens()
            if tokens and tokens.get("access_token"):
                self._log("Token 提取成功")
                result.access_token = tokens["access_token"]
                result.refresh_token = tokens["refresh_token"]
                result.id_token = tokens["id_token"]
                result.success = True
            else:
                # 尝试用 OAuth 后备，其实不需要，只需要报没抓到就可以
                self._log("Session Token 提取失败，如果需要 Codex OAuth，请单独执行 OAuth flow。", "warning")
                # 因为用户要求改成这个流程，这里为了稳妥如果是用 123.py 正常是可以拿到的。
                result.error_message = "无法在会话中提取到 Token"

            if result.success:
                self._log("=" * 60)
                self._log("注册成功!")
                self._log(f"邮箱: {result.email}")
                self._log(f"密码: {result.password}")
                self._log("=" * 60)

            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now().isoformat(),
            }
            return result

        except Exception as e:
            self._log(f"注册过程中发生未预期错误: {e}", "error")
            result.error_message = str(e)
            return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        if not result.success:
            return False
        try:
            settings = get_settings()
            with get_db() as db:
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=settings.openai_client_id,
                    session_token=result.session_token,
                    email_service=self.email_service.service_type.value,
                    email_service_id=self.email_info.get("service_id") if self.email_info else None,
                    account_id=result.account_id,
                    workspace_id=result.workspace_id,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    id_token=result.id_token,
                    proxy_used=self.proxy_url,
                    extra_data=result.metadata,
                    source=result.source
                )
                self._log(f"账户已保存到数据库，ID: {account.id}")
                return True
        except Exception as e:
            self._log(f"保存到数据库失败: {e}", "error")
            return False
