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
import html
import threading
from typing import Optional, Dict, Any, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, unquote

from curl_cffi import requests as cffi_requests
from curl_cffi.requests.models import Response

from .openai.oauth import OAuthManager, OAuthStart
from .http_client import OpenAIHTTPClient, HTTPClientError
from ..services import EmailServiceFactory, BaseEmailService, EmailServiceType
from ..database import crud
from ..database.session import get_db
from ..config.constants import (
    OPENAI_API_ENDPOINTS,
    OPENAI_PAGE_TYPES,
    generate_random_user_info,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_CHARSET,
    AccountStatus,
    TaskStatus,
)
from ..config.settings import get_settings

logger = logging.getLogger(__name__)

_OAUTH_RATE_LIMIT_UNTIL_TS: float = 0.0
_OAUTH_RATE_LIMIT_LOCK = threading.Lock()

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


def _extract_account_id_from_jwt(token: str) -> str:
    """从 JWT 中尝试提取 chatgpt_account_id。"""
    if not token or token.count(".") < 2:
        return ""
    payload_b64 = token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        claims = json.loads(payload.decode("utf-8"))
        auth_claims = claims.get("https://api.openai.com/auth") or {}
        account_id = auth_claims.get("chatgpt_account_id") or claims.get("chatgpt_account_id") or claims.get("account_id")
        return str(account_id or "").strip()
    except Exception:
        return ""

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

@dataclass
class SignupFormResult:
    """提交授权入口表单的结果"""
    success: bool
    page_type: str = ""
    is_existing_account: bool = False
    response_data: Dict[str, Any] = None
    error_message: str = ""

class OAuthPhoneRequiredError(RuntimeError):
    """OAuth 流程被手机号校验拦截。"""

class RegistrationEngine:
    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None,
        token_mode: str = "session",
    ):
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger
        self.task_uuid = task_uuid
        self.token_mode = (token_mode or "session").strip().lower()
        if self.token_mode not in ("session", "oauth"):
            self.token_mode = "session"

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
        self._oauth_session_token = ""

        # 请求超时与重试
        try:
            self.request_timeout = max(20, min(60, int(settings.registration_timeout or 60)))
        except Exception:
            self.request_timeout = 60
        try:
            self.request_retries = max(1, int(settings.registration_max_retries or 3))
        except Exception:
            self.request_retries = 3
        try:
            self.oauth_rate_limit_cooldown_seconds = max(
                0, int(settings.oauth_rate_limit_cooldown_seconds or 0)
            )
        except Exception:
            self.oauth_rate_limit_cooldown_seconds = 0
        try:
            self.oauth_rate_limit_backoff_base_seconds = max(
                1, int(settings.oauth_rate_limit_backoff_base_seconds or 6)
            )
        except Exception:
            self.oauth_rate_limit_backoff_base_seconds = 6
        try:
            self.oauth_rate_limit_backoff_max_seconds = max(
                self.oauth_rate_limit_backoff_base_seconds,
                int(settings.oauth_rate_limit_backoff_max_seconds or 60),
            )
        except Exception:
            self.oauth_rate_limit_backoff_max_seconds = 60

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
        if level == "error":
            logger.error(log_message)
        elif level == "warning":
            logger.warning(log_message)
        else:
            logger.info(log_message)

    def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        label: str = "",
        timeout: Optional[int] = None,
        retries: Optional[int] = None,
        **kwargs: Any,
    ) -> Optional[Response]:
        """带重试的 HTTP 请求封装，防止 curl 超时直接中断流程。"""
        timeout_val = int(timeout or self.request_timeout or 30)
        retry_val = int(retries or self.request_retries or 1)
        last_err: Optional[Exception] = None

        for attempt in range(1, retry_val + 1):
            try:
                return self.session.request(method, url, timeout=timeout_val, **kwargs)
            except Exception as e:
                last_err = e
                if label:
                    self._log(f"{label}请求异常: {e} (第 {attempt}/{retry_val} 次)", "warning")
                else:
                    self._log(f"请求异常: {e} (第 {attempt}/{retry_val} 次)", "warning")
                if attempt < retry_val:
                    time.sleep(min(2.0 * attempt, 6.0))

        if last_err:
            if label:
                self._log(f"{label}请求最终失败: {last_err}", "error")
            else:
                self._log(f"请求最终失败: {last_err}", "error")
        return None

    def _oauth_is_rate_limited(self, message: str) -> bool:
        text = str(message or "").lower()
        if not text:
            return False
        return "429" in text or "rate limit" in text or "too many requests" in text

    def _oauth_compute_backoff_seconds(self, attempt: int) -> int:
        attempt_idx = max(1, int(attempt or 1))
        base = max(1, int(self.oauth_rate_limit_backoff_base_seconds or 1))
        upper = max(base, int(self.oauth_rate_limit_backoff_max_seconds or base))
        return min(upper, base * attempt_idx)

    def _oauth_apply_global_cooldown(self, seconds: int) -> float:
        if seconds <= 0:
            return 0.0
        global _OAUTH_RATE_LIMIT_UNTIL_TS
        target_until = time.time() + float(seconds)
        with _OAUTH_RATE_LIMIT_LOCK:
            if target_until > _OAUTH_RATE_LIMIT_UNTIL_TS:
                _OAUTH_RATE_LIMIT_UNTIL_TS = target_until
            remaining = max(0.0, _OAUTH_RATE_LIMIT_UNTIL_TS - time.time())
        return remaining

    def _oauth_wait_global_cooldown_if_needed(self) -> None:
        with _OAUTH_RATE_LIMIT_LOCK:
            remaining = max(0.0, _OAUTH_RATE_LIMIT_UNTIL_TS - time.time())
        if remaining <= 0:
            return
        wait_seconds = max(1, int(remaining))
        self._log(f"检测到 OAuth 全局冷却，等待 {wait_seconds}s 后继续", "warning")
        time.sleep(remaining)

    def _oauth_handle_rate_limit(self, attempt: int, *, stage: str = "OAuth") -> None:
        backoff_seconds = self._oauth_compute_backoff_seconds(attempt)
        cooldown_seconds = max(backoff_seconds, int(self.oauth_rate_limit_cooldown_seconds or 0))
        remaining = self._oauth_apply_global_cooldown(cooldown_seconds)
        global_cooldown = max(backoff_seconds, int(remaining))
        self._log(
            f"{stage} 命中限流，已设置全局冷却 {global_cooldown}s（本次退避={backoff_seconds}s）",
            "warning",
        )
        if backoff_seconds > 0:
            time.sleep(backoff_seconds)

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
        r = self._request_with_retry(
            "get",
            url,
            label="Authorize",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": f"{self.BASE}/",
                "Upgrade-Insecure-Requests": "1",
            },
            allow_redirects=True,
        )
        if r is None:
            raise Exception("Authorize 请求失败")
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
        r = self._request_with_retry(
            "post",
            url,
            label="Register",
            json={"username": email, "password": password},
            headers=headers,
        )
        if r is None:
            return 0, {"error": "register_request_failed"}
        try:
            data = r.json()
        except Exception:
            data = {"text": r.text[:500]}
        self._log(f"Register -> {r.status_code}")
        return r.status_code, data

    def send_otp(self):
        self._otp_sent_at = time.time()
        url = f"{self.AUTH}/api/accounts/email-otp/send"
        r = self._request_with_retry(
            "get",
            url,
            label="Send OTP",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": f"{self.AUTH}/create-account/password", "Upgrade-Insecure-Requests": "1",
            },
            allow_redirects=True,
        )
        if r is None:
            return 0, {}
        self._log(f"Send OTP -> {r.status_code}")
        return r.status_code, {}

    def validate_otp(self, code: str, sentinel_token: str = None):
        url = f"{self.AUTH}/api/accounts/email-otp/validate"
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Referer": f"{self.AUTH}/email-verification", "Origin": self.AUTH}
        headers.update(_make_trace_headers())
        if sentinel_token: headers["openai-sentinel-token"] = sentinel_token
        r = self._request_with_retry(
            "post",
            url,
            label="Validate OTP",
            json={"code": code},
            headers=headers,
        )
        if r is None:
            return 0, {"error": "validate_otp_request_failed"}
        try:
            data = r.json()
        except Exception:
            data = {"text": r.text[:500]}
        self._log(f"Validate OTP -> {r.status_code}")
        return r.status_code, data

    def create_account(
        self,
        name: str,
        birthdate: str,
        so_token: str = None,
        timeout: Optional[int] = None,
        retries: Optional[int] = None,
    ):
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

        r = self._request_with_retry(
            "post",
            url,
            label="Create Account",
            timeout=timeout,
            retries=retries,
            json=payload,
            headers=headers,
            impersonate=self.impersonate,
        )
        if r is None:
            return 0, {"error": "create_account_request_failed"}

        if r.status_code == 400 and "registration_disallowed" in (r.text or ""):
            self._log("registration_disallowed, 重新获取 sentinel 重试...")
            fresh_token = build_sentinel_token(
                self.session, self.device_id, flow="oauth_create_account",
                user_agent=self.ua, sec_ch_ua=self.sec_ch_ua, impersonate=self.impersonate,
            )
            if fresh_token:
                headers["openai-sentinel-token"] = fresh_token
                r = self._request_with_retry(
                    "post",
                    url,
                    label="Create Account(重试)",
                    timeout=timeout,
                    retries=retries,
                    json=payload,
                    headers=headers,
                    impersonate=self.impersonate,
                )
                if r is None:
                    return 0, {"error": "create_account_retry_failed"}

        try:
            data = r.json()
        except Exception:
            data = {"text": r.text[:500]}
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
        r = self._request_with_retry(
            "get",
            url,
            label="Callback",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
            },
            allow_redirects=True,
        )
        if r is None:
            return None, None
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
            id_token = data.get("idToken") or data.get("id_token") or ""
            account_id = _extract_account_id_from_jwt(id_token) or _extract_account_id_from_jwt(access_token)
            return {
                "access_token": access_token,
                "refresh_token": data.get("refreshToken") or data.get("refresh_token") or "",
                "id_token": id_token,
                "account_id": account_id,
            }
        except: return None

    def _get_session_cookie(self) -> str:
        return (
            self.session.cookies.get("__Secure-next-auth.session-token", domain=".chatgpt.com")
            or self.session.cookies.get("__Secure-next-auth.session-token", domain="chatgpt.com")
            or ""
        )

    def _extract_oauth_state(self, url: str, text: str = "") -> Optional[str]:
        """尝试从 URL 或 HTML 文本中提取 OAuth state。"""
        try:
            state = parse_qs(urlparse(url).query).get("state", [None])[0]
            if state:
                return state
        except Exception:
            pass

        if text:
            for pattern in (
                r'name="state" value="([^"]+)"',
                r'"state"\s*:\s*"([^"]+)"',
                r"state=([^&\"'>]+)",
            ):
                match = re.search(pattern, text)
                if match:
                    return html.unescape(match.group(1))
        return None

    def _extract_redirect_from_html(self, text: str, redirect_uri: str) -> Optional[str]:
        """从 HTML 中抽取回调地址（meta refresh / window.location / 链接）。"""
        if not text:
            return None

        patterns = (
            r'http-equiv=["\']refresh["\']\s+content=["\']\d+;\s*url=([^"\']+)["\']',
            r'window\.location(?:\.href)?\s*=\s*"([^"]+)"',
            r'location\.href\s*=\s*"([^"]+)"',
            r'location\s*=\s*"([^"]+)"',
        )
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                candidate = html.unescape(match.group(1))
                if candidate.startswith(redirect_uri):
                    return candidate

        for match in re.findall(r"https?://[^\s\"'>]+", text):
            if match.startswith(redirect_uri):
                return match

        return None

    def _extract_hidden_inputs(self, text: str) -> Dict[str, str]:
        """从 HTML 表单中提取隐藏字段（type=hidden）。"""
        if not text:
            return {}
        inputs: Dict[str, str] = {}
        for tag in re.findall(r"<input[^>]+>", text, flags=re.IGNORECASE):
            if not re.search(r'type=["\']hidden["\']', tag, flags=re.IGNORECASE):
                continue
            name_match = re.search(r'name=["\']([^"\']+)["\']', tag, flags=re.IGNORECASE)
            if not name_match:
                continue
            value_match = re.search(r'value=["\']([^"\']*)["\']', tag, flags=re.IGNORECASE)
            name = html.unescape(name_match.group(1))
            value = html.unescape(value_match.group(1)) if value_match else ""
            inputs[name] = value
        return inputs

    def _extract_form_action(self, text: str, keyword: str) -> Optional[str]:
        """从 HTML 中抽取指定表单 action。"""
        if not text:
            return None
        for tag in re.findall(r"<form[^>]+>", text, flags=re.IGNORECASE):
            action_match = re.search(r'action=["\']([^"\']+)["\']', tag, flags=re.IGNORECASE)
            if not action_match:
                continue
            action = html.unescape(action_match.group(1))
            if keyword not in action:
                continue
            if action.startswith("/"):
                return urljoin(self.AUTH, action)
            return action
        return None

    def _extract_first_form_action(self, text: str) -> Optional[str]:
        """提取页面中第一个表单 action。"""
        if not text:
            return None
        for tag in re.findall(r"<form[^>]+>", text, flags=re.IGNORECASE):
            action_match = re.search(r'action=["\\\']([^"\\\']+)["\\\']', tag, flags=re.IGNORECASE)
            if not action_match:
                continue
            action = html.unescape(action_match.group(1))
            if action.startswith("/"):
                return urljoin(self.AUTH, action)
            return action
        return None

    def _extract_submit_field(self, text: str) -> Dict[str, str]:
        """提取“继续/同意”按钮字段，用于模拟点击提交。"""
        if not text:
            return {}

        consent_keywords = ("continue", "继续", "allow", "同意", "accept", "authorize", "授权")

        # 优先匹配 button（type=submit 或省略 type）
        for tag in re.findall(r"<button[^>]*>.*?</button>", text, flags=re.IGNORECASE | re.DOTALL):
            open_tag_match = re.search(r"<button[^>]*>", tag, flags=re.IGNORECASE)
            if not open_tag_match:
                continue
            open_tag = open_tag_match.group(0)

            type_match = re.search(r'type=["\\\']([^"\\\']+)["\\\']', open_tag, flags=re.IGNORECASE)
            if type_match and (type_match.group(1) or "").strip().lower() not in ("submit", ""):
                continue

            inner_text = re.sub(r"<[^>]+>", "", tag)
            inner_text = html.unescape(inner_text).strip().lower()
            attrs_text = html.unescape(open_tag).lower()
            value_match = re.search(r'value=["\\\']([^"\\\']*)["\\\']', open_tag, flags=re.IGNORECASE)
            value_text = html.unescape(value_match.group(1)).strip().lower() if value_match else ""
            if not any(key in f"{inner_text} {attrs_text} {value_text}" for key in consent_keywords):
                continue

            name_match = re.search(r'name=["\\\']([^"\\\']+)["\\\']', open_tag, flags=re.IGNORECASE)
            if name_match:
                return {
                    html.unescape(name_match.group(1)): html.unescape(value_match.group(1)) if value_match else "1"
                }
            return {}

        # 回退匹配 input[type=submit|button]
        for tag in re.findall(r"<input[^>]+>", text, flags=re.IGNORECASE):
            type_match = re.search(r'type=["\\\']([^"\\\']+)["\\\']', tag, flags=re.IGNORECASE)
            input_type = (type_match.group(1) if type_match else "").strip().lower()
            if input_type not in ("submit", "button"):
                continue

            value_match = re.search(r'value=["\\\']([^"\\\']*)["\\\']', tag, flags=re.IGNORECASE)
            value_text = html.unescape(value_match.group(1)).strip().lower() if value_match else ""
            attrs_text = html.unescape(tag).lower()
            if not any(key in f"{attrs_text} {value_text}" for key in consent_keywords):
                continue

            name_match = re.search(r'name=["\\\']([^"\\\']+)["\\\']', tag, flags=re.IGNORECASE)
            if name_match:
                return {html.unescape(name_match.group(1)): html.unescape(value_match.group(1)) if value_match else "1"}
            return {}

        return {}

    def _extract_navigation_url_from_html(self, text: str, base_url: str = "") -> Optional[str]:
        """从 HTML 中提取前端跳转 URL（允许非 redirect_uri 前缀）。"""
        if not text:
            return None

        def _normalize(candidate: str) -> str:
            value = html.unescape(candidate or "").strip()
            if not value:
                return ""
            if value.startswith("/") and base_url:
                return urljoin(base_url, value)
            return value

        def _is_static_asset(url: str) -> bool:
            lowered = (url or "").lower().split("?", 1)[0].split("#", 1)[0]
            static_suffixes = (
                ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
                ".css", ".js", ".mjs", ".map", ".woff", ".woff2", ".ttf", ".otf",
            )
            if lowered.endswith(static_suffixes):
                return True
            if "auth-cdn.oaistatic.com/assets/" in lowered:
                return True
            return False

        patterns = (
            r'http-equiv=["\']refresh["\']\s+content=["\']\d+;\s*url=([^"\']+)["\']',
            r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\s*=\s*["\']([^"\']+)["\']',
        )
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if not match:
                continue
            candidate = _normalize(match.group(1) or "")
            if not candidate or _is_static_asset(candidate):
                continue
            return candidate

        preferred_candidates: list[str] = []
        fallback_candidates: list[str] = []
        for match in re.findall(r"https?://[^\s\"'>]+", text):
            candidate = _normalize(match or "")
            if not candidate or _is_static_asset(candidate):
                continue

            lowered = candidate.lower()
            if any(
                marker in lowered
                for marker in (
                    "code=",
                    "/oauth",
                    "/authorize",
                    "/consent",
                    "/callback",
                    "redirect_uri=",
                    "/workspace",
                    "/organization",
                    "/continue",
                )
            ):
                preferred_candidates.append(candidate)
            else:
                fallback_candidates.append(candidate)

        if preferred_candidates:
            return preferred_candidates[0]
        if fallback_candidates:
            for candidate in fallback_candidates:
                try:
                    parsed = urlparse(candidate)
                    host = (parsed.netloc or "").lower()
                    if host in ("auth.openai.com", "localhost", "127.0.0.1"):
                        return candidate
                except Exception:
                    continue

        return None

    def _extract_workspace_id_from_html(self, text: str) -> Optional[str]:
        """从 consent 页面 HTML 中提取 workspace_id。"""
        if not text:
            return None
        try:
            patterns = (
                r'name=["\']workspace_id["\'][^>]*value=["\']([^"\']+)["\']',
                r'"workspace_id"\s*:\s*"([^"]+)"',
                r'"workspaceId"\s*:\s*"([^"]+)"',
            )
            for pattern in patterns:
                match = re.search(pattern, text, flags=re.IGNORECASE)
                if not match:
                    continue
                workspace_id = str(html.unescape(match.group(1) or "")).strip()
                if workspace_id:
                    return workspace_id
        except Exception:
            return None
        return None

    def _oauth_submit_authorize_continue_api(
        self,
        session: cffi_requests.Session,
        page_url: str,
        redirect_uri: str,
        workspace_id_hint: str = "",
    ) -> Optional[str]:
        """Consent 兜底：调用 authorize/continue API 后继续提取 code。"""
        payload_candidates = ({"action": "default"}, {"action": "accept"}, {})
        for payload in payload_candidates:
            try:
                resp = session.post(
                    OPENAI_API_ENDPOINTS["signup"],
                    headers={
                        "referer": page_url,
                        "accept": "application/json",
                        "content-type": "application/json",
                    },
                    data=json.dumps(payload),
                    timeout=20,
                    allow_redirects=False,
                )
            except Exception as e:
                self._log(f"Consent API 兜底请求异常: {e}", "warning")
                continue

            self._log(f"Consent API 兜底状态: {resp.status_code} (payload={payload})")

            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                self._raise_if_phone_required(url=loc, stage="OAuth Consent API 兜底(Location)")
                code = _extract_code_from_url(loc)
                if code:
                    return code
                if loc:
                    code = self._oauth_follow_and_extract_code(session, loc)
                    if code:
                        return code
                continue

            continue_url = ""
            page_type = ""
            response_text = resp.text or ""
            if resp.status_code == 200:
                try:
                    resp_data = resp.json() if response_text else {}
                except Exception:
                    resp_data = {}
                continue_url = str((resp_data or {}).get("continue_url") or "").strip()
                page_type = str((((resp_data or {}).get("page") or {}).get("type")) or "")
                self._raise_if_phone_required(
                    url=continue_url,
                    page_type=page_type,
                    text=response_text,
                    stage="OAuth Consent API 兜底",
                )

            if continue_url:
                next_url = continue_url if continue_url.startswith("http") else f"{self.oauth_issuer}{continue_url}"
                code = _extract_code_from_url(next_url) or self._oauth_follow_and_extract_code(session, next_url)
                if code:
                    return code
            elif workspace_id_hint:
                ws_continue_url = self._oauth_select_workspace(session, workspace_id_hint)
                if ws_continue_url:
                    code = self._oauth_follow_and_extract_code(session, ws_continue_url)
                    if code:
                        return code

            callback_url = self._extract_redirect_from_html(response_text, redirect_uri)
            if callback_url:
                code = _extract_code_from_url(callback_url)
                if code:
                    return code

            nav_url = self._extract_navigation_url_from_html(response_text, base_url=str(resp.url))
            if nav_url:
                code = _extract_code_from_url(nav_url) or self._oauth_follow_and_extract_code(session, nav_url)
                if code:
                    return code

        return None

    def _oauth_submit_consent_form(
        self,
        session: cffi_requests.Session,
        page_url: str,
        html_text: str,
        redirect_uri: str,
    ) -> Optional[str]:
        """提交 OAuth 同意页表单，提取授权码。"""
        try:
            action_url: Optional[str] = None
            payload: Dict[str, str] = {}

            forms = re.findall(r"<form[^>]*>.*?</form>", html_text, flags=re.IGNORECASE | re.DOTALL)
            if forms:
                ranked_forms: list[tuple[int, str, Dict[str, str], Dict[str, str]]] = []
                for form_html in forms:
                    open_tag_match = re.search(r"<form[^>]*>", form_html, flags=re.IGNORECASE)
                    if not open_tag_match:
                        continue
                    open_tag = open_tag_match.group(0)
                    action_match = re.search(r'action=["\\\']([^"\\\']*)["\\\']', open_tag, flags=re.IGNORECASE)
                    action_raw = html.unescape((action_match.group(1) if action_match else "").strip())
                    candidate_action = urljoin(page_url, action_raw) if action_raw else page_url

                    candidate_payload = self._extract_hidden_inputs(form_html)
                    submit_payload = self._extract_submit_field(form_html)

                    candidate_text = f"{open_tag} {form_html}".lower()
                    score = 0
                    if "/sign-in-with-chatgpt/codex/consent" in (action_raw or ""):
                        score += 200
                    if "/api/accounts/authorize/continue" in (action_raw or ""):
                        score += 180
                    if any(k in candidate_text for k in ("continue", "继续", "allow", "同意", "accept", "authorize", "授权")):
                        score += 60
                    if submit_payload:
                        score += 30
                    if action_raw:
                        score += 10

                    ranked_forms.append((score, candidate_action, candidate_payload, submit_payload))

                if ranked_forms:
                    ranked_forms.sort(key=lambda item: item[0], reverse=True)
                    best_score, action_url, payload, submit_payload = ranked_forms[0]
                    payload.update(submit_payload)
                    self._log(
                        f"Consent 表单已选中(score={best_score}) action={action_url[:120]}..., "
                        f"hidden={len(payload)}, submit={len(submit_payload)}"
                    )

            if not action_url:
                # 回退旧逻辑：尽力找到 action，没有则默认回发当前页面
                action_url = (
                    self._extract_form_action(html_text, "/sign-in-with-chatgpt/codex/consent")
                    or self._extract_form_action(html_text, "/api/accounts/authorize/continue")
                    or self._extract_first_form_action(html_text)
                    or page_url
                )
                payload = self._extract_hidden_inputs(html_text)
                payload.update(self._extract_submit_field(html_text))

            action_path = ""
            try:
                action_path = (urlparse(action_url).path or "").lower()
            except Exception:
                action_path = (action_url or "").lower()

            # 对 codex consent 页面不强加 action 字段，尽量还原真实表单提交
            needs_default_action = "/api/accounts/authorize/continue" in action_path
            if needs_default_action and "action" not in payload:
                payload["action"] = "default"

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.oauth_issuer,
                "Referer": page_url,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            resp = session.post(
                action_url,
                data=payload,
                headers=headers,
                timeout=30,
                allow_redirects=False,
            )

            self._log(f"Consent 表单提交状态: {resp.status_code}, URL: {str(resp.url)[:120]}...")
            workspace_id_hint = str(payload.get("workspace_id") or "").strip()

            self._raise_if_phone_required(
                url=str(resp.url),
                text=resp.text or "",
                stage="OAuth Consent 提交",
            )

            if resp.status_code == 405 and workspace_id_hint:
                self._log("Consent 表单返回 405，尝试直接选择 workspace 继续授权", "warning")
                ws_continue_url = self._oauth_select_workspace(session, workspace_id_hint)
                if ws_continue_url:
                    code = self._oauth_follow_and_extract_code(session, ws_continue_url)
                    if code:
                        return code

            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                self._raise_if_phone_required(url=loc, stage="OAuth Consent 提交(Location)")
                code = _extract_code_from_url(loc)
                if code:
                    return code
                if loc:
                    return self._oauth_follow_and_extract_code(session, loc)
                return None

            callback_url = self._extract_redirect_from_html(resp.text or "", redirect_uri)
            if callback_url:
                return _extract_code_from_url(callback_url)

            nav_url = self._extract_navigation_url_from_html(resp.text or "", base_url=str(resp.url))
            if nav_url:
                self._log(f"Consent 响应提取到跳转 URL: {nav_url[:120]}...")
                code = _extract_code_from_url(nav_url)
                if code:
                    return code
                code = self._oauth_follow_and_extract_code(session, nav_url)
                if code:
                    return code

            api_fallback_code = self._oauth_submit_authorize_continue_api(
                session,
                page_url=page_url,
                redirect_uri=redirect_uri,
                workspace_id_hint=workspace_id_hint,
            )
            if api_fallback_code:
                return api_fallback_code

            # 页面无直接 callback，尝试继续跟随当前 URL
            return self._oauth_follow_and_extract_code(session, str(resp.url))
        except Exception as e:
            self._log(f"提交 Consent 表单失败: {e}", "warning")
            return None

    def _looks_like_login_page(self, url: str, text: str) -> bool:
        url_lower = (url or "").lower()
        if "/u/login/" in url_lower:
            return True
        if "name=\"username\"" in text or "name=\"password\"" in text:
            return True
        if "login" in url_lower and "auth.openai.com" in url_lower:
            return True
        return False

    def _is_phone_required(self, url: str = "", text: str = "", page_type: str = "") -> bool:
        url_lower = (url or "").lower()
        page_lower = (page_type or "").lower()
        text_lower = (text or "").lower()

        url_hit = any(key in url_lower for key in (
            "add-phone",
            "add_phone",
            "phone-verification",
            "phone_verification",
            "verify-phone",
            "verify_phone",
            "/phone",
            "onboarding",
        ))
        page_hit = any(key in page_lower for key in (
            "phone",
            "add-phone",
            "add_phone",
            "onboarding",
        ))
        text_hit = any(key in text_lower for key in (
            "add-phone",
            "add_phone",
            "phone verification",
            "verify your phone",
            "phone number",
            "phone required",
            "手机号",
        ))

        return url_hit or page_hit or text_hit

    def _raise_if_phone_required(
        self,
        *,
        url: str = "",
        text: str = "",
        page_type: str = "",
        stage: str = "",
    ) -> None:
        if self._is_phone_required(url=url, text=text, page_type=page_type):
            prefix = f"{stage}：" if stage else ""
            msg = f"{prefix}检测到需要手机号验证，OAuth 授权被拦截"
            self._log(msg, "warning")
            raise OAuthPhoneRequiredError(msg)

    def _handle_about_you(self, source: str) -> bool:
        """在 OAuth 登录流程中遇到 about_you 时补全资料并尽量继续授权。"""
        try:
            user_info = generate_random_user_info()
            name = user_info.get("name") or "User"
            birthdate = user_info.get("birthdate") or "1990-01-01"
            self._log(f"{source}命中 about-you，尝试补全资料并继续 OAuth 授权", "warning")
            about_you_timeout = max(8, min(int(self.request_timeout or 30), 25))
            try:
                status, data = self.create_account(
                    name,
                    birthdate,
                    timeout=about_you_timeout,
                    retries=1,
                )
            except TypeError:
                # 兼容旧签名/测试替身：create_account(name, birthdate, so_token=None)
                status, data = self.create_account(name, birthdate)
            if status in (200, 409):
                if status == 409:
                    self._log("about-you 返回 409（资料已存在），视为可继续授权", "warning")
                # callback 失败不阻断，后续继续走 consent/workspace 提取 code
                try:
                    self.callback()
                except Exception as cb_err:
                    self._log(f"about-you 回调阶段异常（忽略继续）: {cb_err}", "warning")
                return True
            if status == 0:
                reason = ""
                if isinstance(data, dict):
                    reason = str(data.get("error") or "")
                self._log(
                    f"about-you 提交超时或请求失败({reason or 'request_failed'})，按可继续授权处理",
                    "warning",
                )
                try:
                    self.callback()
                except Exception as cb_err:
                    self._log(f"about-you 超时后的回调阶段异常（忽略继续）: {cb_err}", "warning")
                return True
            self._log(f"about-you 提交失败: HTTP {status}", "warning")
            return False
        except Exception as e:
            self._log(f"about-you 处理异常: {e}", "warning")
            return False

    def _auth0_submit_identifier(
        self,
        state: str,
        email: str,
        extra_fields: Optional[Dict[str, str]] = None,
        action_url: Optional[str] = None,
    ) -> Response:
        if extra_fields and extra_fields.get("state"):
            state = extra_fields.get("state") or state
        url = action_url or f"{self.AUTH}/u/login/identifier?state={state}"
        payload = {}
        if extra_fields:
            payload.update(extra_fields)
        payload.update({
            "state": state,
            "username": email,
            "js-available": "true",
            "webauthn-available": "true",
            "is-brave": "false",
            "webauthn-platform-available": "true",
            "action": "default",
        })
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.AUTH,
            "Referer": url,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        return self.session.post(
            url,
            data=payload,
            headers=headers,
            allow_redirects=True,
            impersonate=self.impersonate,
        )

    def _auth0_submit_password(
        self,
        state: str,
        email: str,
        password: str,
        extra_fields: Optional[Dict[str, str]] = None,
        action_url: Optional[str] = None,
    ) -> Response:
        if extra_fields and extra_fields.get("state"):
            state = extra_fields.get("state") or state
        url = action_url or f"{self.AUTH}/u/login/password?state={state}"
        payload = {}
        if extra_fields:
            payload.update(extra_fields)
        payload.update({
            "state": state,
            "username": email,
            "password": password,
            "action": "default",
        })
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.AUTH,
            "Referer": url,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        return self.session.post(
            url,
            data=payload,
            headers=headers,
            allow_redirects=True,
            impersonate=self.impersonate,
        )

    def _complete_oauth_login(
        self,
        current_url: str,
        html_text: str,
        email: str,
        password: str,
        redirect_uri: str,
    ) -> Optional[str]:
        state = self._extract_oauth_state(current_url, html_text)
        if not state:
            return None

        # 识别并提交 identifier
        if "/u/login/identifier" in (current_url or "").lower() or "name=\"username\"" in html_text:
            hidden = self._extract_hidden_inputs(html_text)
            if hidden.get("state"):
                state = hidden.get("state") or state
            action_url = self._extract_form_action(html_text, "/u/login/identifier")
            resp = self._auth0_submit_identifier(state, email, extra_fields=hidden, action_url=action_url)
            current_url = str(resp.url)
            html_text = resp.text or ""
            self._raise_if_phone_required(url=current_url, text=html_text, stage="OAuth 登录(Identifier)")
            if current_url.startswith(redirect_uri):
                return current_url

        # 识别并提交 password
        if "/u/login/password" in (current_url or "").lower() or "name=\"password\"" in html_text:
            hidden = self._extract_hidden_inputs(html_text)
            if hidden.get("state"):
                state = hidden.get("state") or state
            action_url = self._extract_form_action(html_text, "/u/login/password")
            resp = self._auth0_submit_password(state, email, password, extra_fields=hidden, action_url=action_url)
            current_url = str(resp.url)
            html_text = resp.text or ""
            self._raise_if_phone_required(url=current_url, text=html_text, stage="OAuth 登录(Password)")
            if current_url.startswith(redirect_uri):
                return current_url

            loc = resp.headers.get("Location") or resp.headers.get("location")
            if loc:
                if loc.startswith("/"):
                    loc = urljoin(current_url, loc)
                self._raise_if_phone_required(url=loc, stage="OAuth 登录(Password 重定向)")
                if loc.startswith(redirect_uri):
                    return loc
                current_url = loc

        callback_url = self._extract_redirect_from_html(html_text, redirect_uri)
        if callback_url:
            return callback_url

        # 再尝试一次纯重定向链路（禁用登录逻辑）
        return self._follow_oauth_redirect(
            current_url,
            redirect_uri,
            allow_login=False,
        )

    def _follow_oauth_redirect(
        self,
        auth_url: str,
        redirect_uri: str,
        email: Optional[str] = None,
        password: Optional[str] = None,
        allow_login: bool = True,
    ) -> Optional[str]:
        """跟随 OAuth 重定向，获取回调 URL（避免访问本地回调地址）。"""
        current = auth_url
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{self.BASE}/",
            "Upgrade-Insecure-Requests": "1",
        }

        for _ in range(12):
            r = self.session.get(
                current,
                headers=headers,
                allow_redirects=False,
                impersonate=self.impersonate,
            )
            self._raise_if_phone_required(url=str(r.url), text=r.text or "", stage="OAuth 重定向")
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location") or r.headers.get("location")
                if not loc:
                    return None
                if loc.startswith("/"):
                    loc = urljoin(current, loc)
                self._raise_if_phone_required(url=loc, stage="OAuth 重定向(Location)")
                if loc.startswith(redirect_uri):
                    return loc
                current = loc
                continue

            text = r.text or ""
            if redirect_uri and redirect_uri in text:
                callback_url = self._extract_redirect_from_html(text, redirect_uri)
                if callback_url:
                    return callback_url

            if allow_login and email and password and self._looks_like_login_page(str(r.url), text):
                return self._complete_oauth_login(str(r.url), text, email, password, redirect_uri)

            return None

        return None

    def _oauth_get_device_id(self, session: cffi_requests.Session, auth_url: str) -> Optional[str]:
        """获取 OAuth 登录流程的 Device ID。"""
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                response = session.get(auth_url, timeout=20)
                did = session.cookies.get("oai-did")
                if did:
                    self._log(f"OAuth Device ID: {did}")
                    return did
                self._log(
                    f"获取 Device ID 失败: 未返回 oai-did Cookie (HTTP {response.status_code}, 第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )
            except Exception as e:
                self._log(
                    f"获取 Device ID 失败: {e} (第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )
            if attempt < max_attempts:
                time.sleep(attempt)
        return None

    def _oauth_submit_auth_start(
        self,
        session: cffi_requests.Session,
        did: str,
        sen_token: Optional[str],
        *,
        screen_hint: str,
        referer: str,
        log_label: str,
        record_existing_account: bool = True,
    ) -> SignupFormResult:
        """提交 OAuth 授权入口表单，返回页面类型。"""
        try:
            request_body = json.dumps({
                "username": {
                    "value": self.email,
                    "kind": "email",
                },
                "screen_hint": screen_hint,
            })

            headers = {
                "referer": referer,
                "accept": "application/json",
                "content-type": "application/json",
            }

            if sen_token:
                sentinel = json.dumps({
                    "p": "",
                    "t": "",
                    "c": sen_token,
                    "id": did,
                    "flow": "authorize_continue",
                })
                headers["openai-sentinel-token"] = sentinel

            response = session.post(
                OPENAI_API_ENDPOINTS["signup"],
                headers=headers,
                data=request_body,
            )

            self._log(f"{log_label}状态: {response.status_code}")

            if response.status_code != 200:
                return SignupFormResult(
                    success=False,
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                )

            try:
                response_data = response.json()
                page_type = response_data.get("page", {}).get("type", "")
                self._log(f"响应页面类型: {page_type}")

                continue_url = str(response_data.get("continue_url") or "")
                if self._is_phone_required(
                    url=continue_url,
                    page_type=page_type,
                    text=json.dumps(response_data, ensure_ascii=False),
                ):
                    self._log("OAuth 授权入口被手机号校验拦截", "warning")
                    return SignupFormResult(
                        success=False,
                        page_type=page_type,
                        response_data=response_data,
                        error_message="PHONE_REQUIRED",
                    )

                is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]
                if is_existing:
                    self._otp_sent_at = time.time()
                    if record_existing_account:
                        self._log("检测到已注册账号，进入验证码流程")

                return SignupFormResult(
                    success=True,
                    page_type=page_type,
                    is_existing_account=is_existing,
                    response_data=response_data
                )
            except Exception as parse_error:
                self._log(f"解析响应失败: {parse_error}", "warning")
                return SignupFormResult(success=True)

        except Exception as e:
            self._log(f"{log_label}失败: {e}", "error")
            return SignupFormResult(success=False, error_message=str(e))

    def _oauth_submit_login_start(
        self,
        session: cffi_requests.Session,
        did: str,
        sen_token: Optional[str],
    ) -> SignupFormResult:
        return self._oauth_submit_auth_start(
            session,
            did,
            sen_token,
            screen_hint="login",
            referer="https://auth.openai.com/log-in",
            log_label="提交登录入口",
            record_existing_account=False,
        )

    def _oauth_submit_login_password(self, session: cffi_requests.Session) -> SignupFormResult:
        """提交登录密码，推进到邮箱验证码页面。"""
        try:
            response = session.post(
                OPENAI_API_ENDPOINTS["password_verify"],
                headers={
                    "referer": "https://auth.openai.com/log-in/password",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=json.dumps({"password": self.password}),
            )

            self._log(f"提交登录密码状态: {response.status_code}")

            if response.status_code != 200:
                return SignupFormResult(
                    success=False,
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                )

            response_data = response.json()
            page_type = response_data.get("page", {}).get("type", "")
            self._log(f"登录密码响应页面类型: {page_type}")

            continue_url = str(response_data.get("continue_url") or "")
            if self._is_phone_required(
                url=continue_url,
                page_type=page_type,
                text=json.dumps(response_data, ensure_ascii=False),
            ):
                self._log("登录密码阶段被手机号校验拦截", "warning")
                return SignupFormResult(
                    success=False,
                    page_type=page_type,
                    response_data=response_data,
                    error_message="PHONE_REQUIRED",
                )

            is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]
            if is_existing:
                self._otp_sent_at = time.time()
                self._log("登录密码校验通过，等待系统发送验证码")

            return SignupFormResult(
                success=True,
                page_type=page_type,
                is_existing_account=is_existing,
                response_data=response_data,
            )

        except Exception as e:
            self._log(f"提交登录密码失败: {e}", "error")
            return SignupFormResult(success=False, error_message=str(e))

    def _oauth_validate_verification_code(self, session: cffi_requests.Session, code: str) -> bool:
        """验证验证码（OAuth 登录流程）。"""
        try:
            response = session.post(
                OPENAI_API_ENDPOINTS["validate_otp"],
                headers={
                    "referer": "https://auth.openai.com/email-verification",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=json.dumps({"code": code}),
            )
            self._log(f"验证码校验状态: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            self._log(f"验证验证码失败: {e}", "error")
            return False

    def _extract_cookie_values(self, session: cffi_requests.Session, name: str) -> list[str]:
        """从 cookie jar 中尽可能取出指定名称的 cookie 值。"""
        values: list[str] = []
        try:
            direct = session.cookies.get(name)
            if direct:
                values.append(str(direct))
        except Exception:
            pass

        # 尝试指定域名
        for domain in ("auth.openai.com", ".openai.com", "openai.com"):
            try:
                direct = session.cookies.get(name, domain=domain)
                if direct:
                    values.append(str(direct))
            except Exception:
                pass

        # 遍历 cookie jar
        try:
            jar = getattr(session.cookies, "jar", None)
            if jar is not None:
                for item in list(jar):
                    if str(getattr(item, "name", "")) == name:
                        value = str(getattr(item, "value", "") or "").strip()
                        if value:
                            values.append(value)
        except Exception:
            pass

        # 去重保持顺序
        seen = set()
        uniq: list[str] = []
        for v in values:
            if v not in seen:
                seen.add(v)
                uniq.append(v)
        return uniq

    def _decode_oauth_session_cookie(self, raw_value: str) -> Optional[Dict[str, Any]]:
        """解析 oai-client-auth-session cookie（兼容 URL 编码/引号/JWT 片段）。"""
        if not raw_value:
            return None
        candidates = [raw_value]
        try:
            decoded = unquote(raw_value)
            if decoded != raw_value:
                candidates.append(decoded)
        except Exception:
            pass

        for candidate in candidates:
            try:
                value = candidate.strip()
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                part = value.split(".")[0] if "." in value else value
                pad = "=" * ((4 - (len(part) % 4)) % 4)
                decoded = base64.urlsafe_b64decode((part + pad).encode("ascii"))
                data = json.loads(decoded.decode("utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception:
                continue
        return None

    def _extract_workspace_id_from_cookie(self, raw_value: str) -> Optional[str]:
        """从授权相关 Cookie 值中提取 workspace_id。"""
        if not raw_value:
            return None

        candidates = [raw_value]
        if "." in raw_value:
            candidates.extend(str(raw_value).split("."))

        for candidate in candidates:
            payload = self._decode_oauth_session_cookie(candidate)
            if not isinstance(payload, dict):
                continue

            workspaces = payload.get("workspaces") or []
            if isinstance(workspaces, list):
                for workspace in workspaces:
                    workspace_id = str((workspace or {}).get("id") or "").strip()
                    if workspace_id:
                        return workspace_id

            for key in ("workspace_id", "workspaceId"):
                workspace_id = str(payload.get(key) or "").strip()
                if workspace_id:
                    return workspace_id

        return None

    def _oauth_get_workspace_id(
        self,
        session: cffi_requests.Session,
        consent_url: str = "",
    ) -> Optional[str]:
        """获取 Workspace ID（OAuth 登录流程）。"""
        try:
            cookie_names = (
                "oai-client-auth-session",
                "oai_client_auth_session",
                "oai-client-auth-info",
                "oai_client_auth_info",
            )
            for cookie_name in cookie_names:
                cookie_values = self._extract_cookie_values(session, cookie_name)
                for raw_cookie in cookie_values:
                    workspace_id = self._extract_workspace_id_from_cookie(raw_cookie)
                    if workspace_id:
                        self._log(f"Workspace ID: {workspace_id} (from {cookie_name})")
                        return workspace_id

            page_candidates = []
            if consent_url:
                page_candidates.append(consent_url)
            page_candidates.append(f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent")
            pattern = re.compile(r'"workspace_id"\s*:\s*"([^"]+)"')
            for page_url in page_candidates:
                try:
                    response = session.get(page_url, timeout=15)
                    workspace_id_from_html = self._extract_workspace_id_from_html(response.text or "")
                    if workspace_id_from_html:
                        self._log(f"Workspace ID: {workspace_id_from_html} (from html)")
                        return workspace_id_from_html
                    match = pattern.search(response.text or "")
                    if match:
                        workspace_id = str(match.group(1) or "").strip()
                        if workspace_id:
                            self._log(f"Workspace ID: {workspace_id} (from page)")
                            return workspace_id
                except Exception:
                    continue

            self._log("未能从 Cookie/页面提取 workspace_id", "error")
            return None

        except Exception as e:
            self._log(f"获取 Workspace ID 失败: {e}", "error")
            return None

    def _oauth_select_workspace(self, session: cffi_requests.Session, workspace_id: str) -> Optional[str]:
        """选择 Workspace（OAuth 登录流程）。"""
        try:
            response = session.post(
                OPENAI_API_ENDPOINTS["select_workspace"],
                headers={
                    "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    "content-type": "application/json",
                },
                data=json.dumps({"workspace_id": workspace_id}),
            )

            if response.status_code != 200:
                self._log(f"选择 workspace 失败: {response.status_code}", "error")
                self._log(f"响应: {response.text[:200]}", "warning")
                return None

            continue_url = str((response.json() or {}).get("continue_url") or "").strip()
            if not continue_url:
                self._log("workspace/select 响应里缺少 continue_url", "error")
                return None

            self._log(f"Continue URL: {continue_url[:100]}...")
            return continue_url

        except Exception as e:
            self._log(f"选择 Workspace 失败: {e}", "error")
            return None

    def _oauth_follow_redirects(self, session: cffi_requests.Session, start_url: str) -> Optional[str]:
        """跟随重定向链，寻找回调 URL（OAuth 登录流程）。"""
        try:
            current_url = start_url
            max_redirects = 6

            for i in range(max_redirects):
                self._log(f"重定向 {i+1}/{max_redirects}: {current_url[:100]}...")
                response = session.get(current_url, allow_redirects=False, timeout=15)
                self._raise_if_phone_required(
                    url=str(response.url),
                    text=response.text or "",
                    stage="OAuth 重定向链",
                )

                location = response.headers.get("Location") or ""
                if response.status_code not in [301, 302, 303, 307, 308]:
                    self._log(f"非重定向状态码: {response.status_code}")
                    break
                if not location:
                    self._log("重定向响应缺少 Location 头")
                    break

                next_url = urljoin(current_url, location)
                self._raise_if_phone_required(url=next_url, stage="OAuth 重定向链(Location)")
                if "code=" in next_url and "state=" in next_url:
                    self._log(f"找到回调 URL: {next_url[:100]}...")
                    return next_url
                current_url = next_url

            self._log("未能在重定向链中找到回调 URL", "error")
            return None

        except Exception as e:
            self._log(f"跟随重定向失败: {e}", "error")
            return None

    def _oauth_follow_and_extract_code(self, session: cffi_requests.Session, url: str, max_depth: int = 10) -> Optional[str]:
        """跟随跳转链并提取 code（OAuth 授权流程兜底）。"""
        if not url:
            return None
        current_url = url
        for _ in range(max_depth):
            if current_url.startswith("/"):
                current_url = f"{self.oauth_issuer}{current_url}"
            try:
                resp = session.get(current_url, allow_redirects=False, timeout=15)
            except Exception as e:
                # 有时重定向到 localhost 会触发连接异常，尝试从错误信息里抓 code
                m = re.search(r"(https?://localhost[^\s'\"]+)", str(e))
                if m:
                    return _extract_code_from_url(m.group(1))
                return None

            self._raise_if_phone_required(
                url=str(resp.url),
                text=resp.text or "",
                stage="OAuth 跟随跳转",
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                self._raise_if_phone_required(url=loc, stage="OAuth 跟随跳转(Location)")
                code = _extract_code_from_url(loc)
                if code:
                    return code
                if not loc:
                    return None
                current_url = urljoin(current_url, loc)
                continue

            if resp.status_code == 200:
                return _extract_code_from_url(str(resp.url))

            return None
        return None

    def _oauth_exchange_auth_code(self, session: cffi_requests.Session, oauth_start: OAuthStart) -> Optional[str]:
        """从 consent/workspace/organization 流程中提取 OAuth code。"""
        consent_url = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
        auth_code: Optional[str] = None

        # 0) 先访问本次 OAuth authorize 入口，确保 state/code_challenge 上下文是当前这次
        try:
            resp_entry = session.get(
                oauth_start.auth_url,
                headers={"referer": f"{self.oauth_issuer}/log-in"},
                allow_redirects=False,
                timeout=30,
            )
            self._raise_if_phone_required(
                url=str(resp_entry.url),
                text=resp_entry.text or "",
                stage="OAuth Authorize 入口",
            )
            self._log(f"OAuth Authorize 入口状态: {resp_entry.status_code}")
            if resp_entry.status_code in (301, 302, 303, 307, 308):
                loc = resp_entry.headers.get("Location", "")
                self._raise_if_phone_required(url=loc, stage="OAuth Authorize 入口(Location)")
                entry_next = urljoin(oauth_start.auth_url, loc) if loc else ""
                if entry_next:
                    auth_code = _extract_code_from_url(entry_next)
                    if "/sign-in-with-chatgpt/codex/consent" in entry_next:
                        consent_url = entry_next
                        self._log(f"OAuth Authorize 入口跳转到 Consent: {consent_url[:120]}...")
                    if not auth_code and "/sign-in-with-chatgpt/codex/consent" not in entry_next:
                        auth_code = self._oauth_follow_and_extract_code(session, entry_next)
            elif resp_entry.status_code == 200:
                entry_callback = self._extract_redirect_from_html(resp_entry.text or "", oauth_start.redirect_uri)
                if entry_callback:
                    auth_code = _extract_code_from_url(entry_callback)
                if not auth_code and "/sign-in-with-chatgpt/codex/consent" in str(resp_entry.url):
                    consent_url = str(resp_entry.url)
        except Exception as e:
            m = re.search(r"(https?://localhost[^\s'\"]+)", str(e))
            if m:
                auth_code = _extract_code_from_url(m.group(1))

        # 1) 直接访问 consent，看是否 302 带 code
        if not auth_code:
            try:
                resp_consent = session.get(
                    consent_url,
                    headers={"referer": f"{self.oauth_issuer}/log-in"},
                    allow_redirects=False,
                    timeout=30,
                )
                self._raise_if_phone_required(
                    url=str(resp_consent.url),
                    text=resp_consent.text or "",
                    stage="OAuth Consent",
                )
                if resp_consent.status_code in (301, 302, 303, 307, 308):
                    loc = resp_consent.headers.get("Location", "")
                    self._raise_if_phone_required(url=loc, stage="OAuth Consent(Location)")
                    auth_code = _extract_code_from_url(loc) or self._oauth_follow_and_extract_code(session, loc)
                elif resp_consent.status_code == 200:
                    consent_workspace_id = self._extract_workspace_id_from_html(resp_consent.text or "")
                    if consent_workspace_id:
                        self._log(f"Consent 页面提取到 workspace_id: {consent_workspace_id}")
                        ws_continue_url = self._oauth_select_workspace(session, consent_workspace_id)
                        if ws_continue_url:
                            auth_code = self._oauth_follow_and_extract_code(session, ws_continue_url)
                    if not auth_code:
                        auth_code = self._oauth_submit_consent_form(
                            session,
                            page_url=str(resp_consent.url),
                            html_text=resp_consent.text or "",
                            redirect_uri=oauth_start.redirect_uri,
                        )
            except Exception as e:
                m = re.search(r"(https?://localhost[^\s'\"]+)", str(e))
                if m:
                    auth_code = _extract_code_from_url(m.group(1))

        # 2) 走 workspace / organization 流程
        if not auth_code:
            workspace_id = self._oauth_get_workspace_id(session, consent_url=consent_url)
            if workspace_id:
                headers = {
                    "referer": consent_url,
                    "content-type": "application/json",
                }
                try:
                    resp_ws = session.post(
                        OPENAI_API_ENDPOINTS["select_workspace"],
                        headers=headers,
                        data=json.dumps({"workspace_id": workspace_id}),
                        timeout=30,
                        allow_redirects=False,
                    )
                    if resp_ws.status_code in (301, 302, 303, 307, 308):
                        loc = resp_ws.headers.get("Location", "")
                        self._raise_if_phone_required(url=loc, stage="OAuth Workspace(Location)")
                        auth_code = _extract_code_from_url(loc) or self._oauth_follow_and_extract_code(session, loc)
                    elif resp_ws.status_code == 200:
                        ws_data = resp_ws.json() if resp_ws.text else {}
                        ws_next = str(ws_data.get("continue_url") or "")
                        ws_page = str(((ws_data.get("page") or {}).get("type")) or "")
                        self._raise_if_phone_required(
                            url=ws_next,
                            page_type=ws_page,
                            text=json.dumps(ws_data, ensure_ascii=False),
                            stage="OAuth Workspace",
                        )

                        if "organization" in ws_next or "organization" in ws_page:
                            org_url = ws_next if ws_next.startswith("http") else f"{self.oauth_issuer}{ws_next}"
                            org_id = None
                            project_id = None
                            ws_orgs = (ws_data.get("data") or {}).get("orgs", []) if isinstance(ws_data, dict) else []
                            if ws_orgs:
                                org_id = (ws_orgs[0] or {}).get("id")
                                projects = (ws_orgs[0] or {}).get("projects", [])
                                if projects:
                                    project_id = (projects[0] or {}).get("id")

                            if org_id:
                                body = {"org_id": org_id}
                                if project_id:
                                    body["project_id"] = project_id
                                resp_org = session.post(
                                    f"{self.oauth_issuer}/api/accounts/organization/select",
                                    json=body,
                                    headers={
                                        "referer": org_url,
                                        "content-type": "application/json",
                                    },
                                    timeout=30,
                                    allow_redirects=False,
                                )
                                if resp_org.status_code in (301, 302, 303, 307, 308):
                                    loc = resp_org.headers.get("Location", "")
                                    self._raise_if_phone_required(url=loc, stage="OAuth Organization(Location)")
                                    auth_code = _extract_code_from_url(loc) or self._oauth_follow_and_extract_code(session, loc)
                                elif resp_org.status_code == 200:
                                    org_next = str((resp_org.json() or {}).get("continue_url") or "")
                                    if org_next:
                                        full_next = org_next if org_next.startswith("http") else f"{self.oauth_issuer}{org_next}"
                                        self._raise_if_phone_required(url=full_next, stage="OAuth Organization")
                                        auth_code = self._oauth_follow_and_extract_code(session, full_next)
                            else:
                                self._raise_if_phone_required(url=org_url, stage="OAuth Organization")
                                auth_code = self._oauth_follow_and_extract_code(session, org_url)
                        elif ws_next:
                            full_next = ws_next if ws_next.startswith("http") else f"{self.oauth_issuer}{ws_next}"
                            self._raise_if_phone_required(url=full_next, stage="OAuth Workspace")
                            auth_code = self._oauth_follow_and_extract_code(session, full_next)
                except Exception as e:
                    self._log(f"OAuth workspace/organization 处理异常: {e}", "warning")

        # 3) 最后兜底：允许自动重定向
        if not auth_code:
            try:
                resp_fallback = session.get(
                    consent_url,
                    headers={"referer": f"{self.oauth_issuer}/log-in"},
                    allow_redirects=True,
                    timeout=30,
                )
                self._raise_if_phone_required(
                    url=str(resp_fallback.url),
                    text=resp_fallback.text or "",
                    stage="OAuth Consent(兜底)",
                )
                auth_code = _extract_code_from_url(str(resp_fallback.url))
                if not auth_code and getattr(resp_fallback, "history", None):
                    for hist in resp_fallback.history:
                        loc = hist.headers.get("Location", "")
                        self._raise_if_phone_required(url=loc, stage="OAuth Consent(兜底 Location)")
                        auth_code = _extract_code_from_url(loc)
                        if auth_code:
                            break
            except Exception as e:
                m = re.search(r"(https?://localhost[^\s'\"]+)", str(e))
                if m:
                    auth_code = _extract_code_from_url(m.group(1))

        return auth_code

    def _oauth_handle_callback(
        self,
        oauth_manager: OAuthManager,
        oauth_start: OAuthStart,
        callback_url: str,
    ) -> Optional[Dict[str, Any]]:
        """处理 OAuth 回调（OAuth 登录流程）。"""
        try:
            self._log("处理 OAuth 回调...")
            token_info = oauth_manager.handle_callback(
                callback_url=callback_url,
                expected_state=oauth_start.state,
                code_verifier=oauth_start.code_verifier
            )
            self._log("OAuth 授权成功")
            return token_info
        except Exception as e:
            self._log(f"处理 OAuth 回调失败: {e}", "error")
            return None

    def _get_oauth_tokens_via_existing_session(self) -> Optional[Dict[str, Any]]:
        """复用当前会话尝试直接完成 OAuth 授权（避免二次登录）。"""
        try:
            if self.session is None:
                return None

            self._log("尝试复用现有会话获取 OAuth Token")
            oauth_manager = OAuthManager(
                client_id=self.oauth_client_id,
                auth_url=f"{self.oauth_issuer}/oauth/authorize",
                token_url=f"{self.oauth_issuer}/oauth/token",
                redirect_uri=self.oauth_redirect_uri,
                scope="openid email profile offline_access",
                proxy_url=self.proxy_url,
            )
            max_attempts = 3
            for attempt in range(1, max_attempts + 1):
                try:
                    self._oauth_wait_global_cooldown_if_needed()
                    oauth_start = oauth_manager.start_oauth()
                    self._log(f"OAuth URL 已生成(复用会话): {oauth_start.auth_url[:80]}...")

                    # 去掉 prompt=login，避免强制重新登录
                    try:
                        parsed = urlparse(oauth_start.auth_url)
                        query = parse_qs(parsed.query, keep_blank_values=True)
                        params = {k: (v[-1] if isinstance(v, list) and v else v) for k, v in query.items()}
                        params.pop("prompt", None)
                        authorize_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                    except Exception:
                        authorize_url = oauth_start.auth_url

                    callback_url = self._follow_oauth_redirect(
                        authorize_url,
                        oauth_start.redirect_uri,
                        allow_login=False,
                    )
                    if not callback_url:
                        self._log("复用会话未拿到 OAuth 回调", "warning")
                        continue

                    token_info = self._oauth_handle_callback(oauth_manager, oauth_start, callback_url)
                    if not token_info:
                        self._log("复用会话处理 OAuth 回调失败，准备重试", "warning")
                        continue

                    self._oauth_session_token = self._get_session_cookie()
                    return token_info
                except OAuthPhoneRequiredError:
                    self._log(
                        f"复用会话遇到手机号校验拦截，重新获取 OAuth URL 重试 ({attempt}/{max_attempts})",
                        "warning",
                    )
                    if attempt >= max_attempts:
                        return None
                except Exception as e:
                    error_text = str(e)
                    if self._oauth_is_rate_limited(error_text):
                        self._oauth_handle_rate_limit(attempt, stage="OAuth 复用会话")
                        return None
                    self._log(f"复用会话 OAuth 异常: {error_text}", "warning")
                    continue

        except Exception as e:
            self._log(f"复用会话 OAuth 失败: {e}", "warning")
            return None

    def _get_oauth_tokens_via_login_flow(self) -> Optional[Dict[str, Any]]:
        """使用旧版 OAuth 登录流程获取 Token（含 refresh_token）。"""
        try:
            oauth_manager = OAuthManager(
                client_id=self.oauth_client_id,
                auth_url=f"{self.oauth_issuer}/oauth/authorize",
                token_url=f"{self.oauth_issuer}/oauth/token",
                redirect_uri=self.oauth_redirect_uri,
                scope="openid email profile offline_access",
                proxy_url=self.proxy_url,
            )
            max_attempts = 3
            last_error = ""
            for attempt in range(1, max_attempts + 1):
                try:
                    self._oauth_wait_global_cooldown_if_needed()
                    self._log(f"尝试 OAuth 登录流程获取 Token（第 {attempt}/{max_attempts} 次）")
                    oauth_start = oauth_manager.start_oauth()
                    self._log(f"OAuth URL 已生成: {oauth_start.auth_url[:80]}...")

                    http_client = OpenAIHTTPClient(proxy_url=self.proxy_url)
                    session = http_client.session

                    did = self._oauth_get_device_id(session, oauth_start.auth_url)
                    if not did:
                        last_error = "获取 Device ID 失败"
                        self._log(last_error, "warning")
                        continue

                    sen_token = http_client.check_sentinel(did)
                    if not sen_token:
                        self._log("Sentinel 校验失败，尝试继续 OAuth 登录流程", "warning")

                    login_start = self._oauth_submit_login_start(session, did, sen_token)
                    if not login_start.success:
                        if login_start.error_message == "PHONE_REQUIRED":
                            raise OAuthPhoneRequiredError("登录入口需要手机号验证")
                        last_error = f"登录入口失败: {login_start.error_message or 'unknown'}"
                        self._log(last_error, "warning")
                        if self._oauth_is_rate_limited(last_error):
                            self._oauth_handle_rate_limit(attempt, stage="OAuth 登录")
                            return None
                        continue

                    need_email_otp = True
                    if login_start.page_type == OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]:
                        password_result = self._oauth_submit_login_password(session)
                        if not password_result.success or not password_result.is_existing_account:
                            if password_result.error_message == "PHONE_REQUIRED":
                                raise OAuthPhoneRequiredError("登录密码阶段需要手机号验证")
                            if (password_result.page_type or "") == "about_you":
                                handled_about_you = self._handle_about_you("登录密码阶段")
                                if handled_about_you:
                                    need_email_otp = False
                                    self._log("登录密码阶段 about-you 已处理，继续尝试提取授权码")
                                else:
                                    last_error = "登录密码阶段命中 about-you，补全资料失败"
                                    self._log(last_error, "warning")
                                    continue
                            else:
                                last_error = f"登录密码阶段未进入验证码页面: {password_result.page_type or 'unknown'}"
                                self._log(last_error, "warning")
                                continue
                    elif login_start.page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]:
                        self._log("已进入验证码页面，跳过密码步骤")
                    else:
                        if login_start.page_type == "about_you":
                            handled_about_you = self._handle_about_you("登录入口")
                            if handled_about_you:
                                need_email_otp = False
                                self._log("登录入口 about-you 已处理，继续尝试提取授权码")
                            else:
                                last_error = "登录入口命中 about-you，补全资料失败"
                                self._log(last_error, "warning")
                                continue
                        elif self._is_phone_required(page_type=login_start.page_type):
                            raise OAuthPhoneRequiredError("登录入口需要手机号验证")
                        else:
                            last_error = f"登录入口未进入预期页面: {login_start.page_type}"
                            self._log(last_error, "warning")
                            continue

                    if need_email_otp:
                        self._log("获取邮箱验证码")
                        code = self.wait_for_verification_email(timeout=120)
                        if not code:
                            last_error = "获取邮箱验证码失败"
                            self._log(last_error, "warning")
                            continue

                        self._log("校验邮箱验证码")
                        if not self._oauth_validate_verification_code(session, code):
                            last_error = "验证码校验失败"
                            self._log(last_error, "warning")
                            continue
                    else:
                        self._log("本次流程无需邮箱验证码，直接进入授权码提取")

                    auth_code = self._oauth_exchange_auth_code(session, oauth_start)
                    if not auth_code:
                        self._log("未能从 OAuth consent 流程提取 code，尝试重定向链兜底", "warning")
                        fallback_callback = self._oauth_follow_redirects(session, oauth_start.auth_url)
                        if fallback_callback:
                            token_info = self._oauth_handle_callback(
                                oauth_manager,
                                oauth_start,
                                fallback_callback,
                            )
                            if token_info:
                                self._oauth_session_token = session.cookies.get("__Secure-next-auth.session-token") or ""
                                return token_info
                        self._log("OAuth 重定向链兜底未提取到回调", "error")
                        last_error = "未能从 OAuth consent 流程提取 code"
                        continue

                    callback_url = f"{oauth_start.redirect_uri}?code={auth_code}&state={oauth_start.state}"
                    token_info = self._oauth_handle_callback(oauth_manager, oauth_start, callback_url)
                    if not token_info:
                        last_error = "OAuth 回调处理失败"
                        self._log(last_error, "warning")
                        continue

                    self._oauth_session_token = session.cookies.get("__Secure-next-auth.session-token") or ""
                    return token_info
                except OAuthPhoneRequiredError:
                    self._log(
                        f"OAuth 登录流程被手机号校验拦截，重新获取 OAuth URL 重试 ({attempt}/{max_attempts})",
                        "warning",
                    )
                    if attempt >= max_attempts:
                        return None
                except Exception as e:
                    last_error = str(e)
                    if self._oauth_is_rate_limited(last_error):
                        self._oauth_handle_rate_limit(attempt, stage="OAuth 登录")
                        return None
                    self._log(f"OAuth 登录流程异常: {e}，准备重试", "warning")
                    continue

            if last_error:
                self._log(f"OAuth 登录流程最终失败: {last_error}", "warning")
            return None

        except Exception as e:
            self._log(f"OAuth 登录流程失败: {e}", "warning")
            return None

    def get_oauth_tokens(self) -> Optional[Dict[str, Any]]:
        """通过 OAuth 授权获取 access_token/refresh_token。"""
        try:
            self._log("OAuth 授权流程：优先复用现有会话获取 Token")
            tokens = self._get_oauth_tokens_via_existing_session()
            if tokens and tokens.get("access_token"):
                return tokens

            self._log("复用会话失败，回退旧版 OAuth 登录流程", "warning")
            return self._get_oauth_tokens_via_login_flow()
        except Exception as e:
            self._log(f"OAuth 授权失败: {e}", "warning")
            return None

    # ====== Main Run ======

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)
        token_source = "unknown"
        issued_client_id = ""
        token_audience = []
        token_scope = ""
        auth_profile = "unknown"
        registration_completed = False

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
            registration_completed = True

            # 抓取 Token
            if self.token_mode == "oauth":
                self._log("尝试通过 OAuth 授权获取 Token（含 refresh_token）")
                tokens = self.get_oauth_tokens()
                if tokens and tokens.get("access_token"):
                    self._log("OAuth Token 获取成功")
                    result.access_token = tokens.get("access_token") or ""
                    result.refresh_token = tokens.get("refresh_token") or ""
                    result.id_token = tokens.get("id_token") or ""
                    result.account_id = tokens.get("account_id") or result.account_id
                    issued_client_id = str(tokens.get("issued_client_id") or "").strip()
                    token_audience = tokens.get("token_audience") or []
                    if not isinstance(token_audience, list):
                        token_audience = [str(token_audience)]
                    token_scope = str(tokens.get("token_scope") or "").strip()
                    if not result.email and tokens.get("email"):
                        result.email = tokens.get("email")
                    result.success = True
                    token_source = "oauth"
                    auth_profile = "codex_oauth"
                    result.session_token = self._oauth_session_token or self._get_session_cookie()
                else:
                    result.session_token = result.session_token or self._get_session_cookie() or ""
                    self._log("OAuth Token 获取失败（OAuth 模式不回退 Session）", "warning")
                    recent_logs = " ".join(self.logs[-8:]).lower()
                    if self._oauth_is_rate_limited(recent_logs):
                        result.error_message = "OAuth Token 获取失败: rate_limited"
                    else:
                        result.error_message = "OAuth Token 获取失败"
            else:
                self._log("尝试从 ChatGPT Session 提取 Token")
                tokens = self.get_chatgpt_session_tokens()
                if tokens and tokens.get("access_token"):
                    self._log("Token 提取成功")
                    result.access_token = tokens["access_token"]
                    result.refresh_token = tokens["refresh_token"]
                    result.id_token = tokens["id_token"]
                    result.account_id = tokens.get("account_id") or result.account_id
                    result.success = True
                    token_source = "session"
                    auth_profile = "session"
                    result.session_token = self._get_session_cookie()
                else:
                    # 尝试用 OAuth 后备，其实不需要，只需要报没抓到就可以
                    self._log("Session Token 提取失败，如果需要 Codex OAuth，请切换为 OAuth 模式。", "warning")
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
                "email_service_id": self.email_info.get("service_id") if self.email_info else None,
                "proxy_used": self.proxy_url,
                "token_mode": self.token_mode,
                "token_source": token_source,
                "auth_profile": auth_profile,
                "issued_client_id": issued_client_id,
                "token_audience": token_audience,
                "token_scope": token_scope,
                "registration_completed": registration_completed,
                "registered_at": datetime.now().isoformat(),
                "user_agent": self.ua,
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
            metadata = result.metadata or {}
            token_source = str(metadata.get("token_source") or "").strip().lower()
            issued_client_id = str(metadata.get("issued_client_id") or "").strip()
            client_id_for_db = issued_client_id or (
                settings.openai_client_id
                if token_source in {"oauth", "browser_oauth"} and result.refresh_token
                else None
            )
            with get_db() as db:
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=client_id_for_db,
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
