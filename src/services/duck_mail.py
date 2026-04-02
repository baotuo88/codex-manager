"""
DuckMail 邮箱服务实现
兼容 DuckMail 的 accounts/token/messages 接口模型
"""

import inspect
import logging
import random
import re
import string
import time
from datetime import datetime, timezone
from html import unescape
from typing import Any, Dict, List, Optional

from .base import (
    BaseEmailService,
    EmailServiceFactory,
    EmailServiceError,
    EmailServiceType,
    parse_domain_list,
    pick_domain,
)
from ..config.constants import OTP_CODE_PATTERN
from ..core.http_client import HTTPClient, RequestConfig


logger = logging.getLogger(__name__)


class DuckMailService(BaseEmailService):
    """DuckMail 邮箱服务"""

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        super().__init__(EmailServiceType.DUCK_MAIL, name)

        raw_config = config or {}
        mode = str(raw_config.get("mode") or "").strip().lower()
        if mode not in {"custom_api", "duck_official"}:
            # 兼容历史配置：若配置了官方 token/cookie，默认走官方模式
            if raw_config.get("duck_api_token") or raw_config.get("duck_cookie"):
                mode = "duck_official"
            else:
                mode = "custom_api"
        self._mode = mode

        default_config = {
            "mode": self._mode,
            "api_key": "",
            "duck_api_base_url": "https://quack.duckduckgo.com",
            "duck_api_token": "",
            "duck_cookie": "",
            "domain_strategy": "round_robin",
            "password_length": 12,
            "expires_in": None,
            "receiver_service_type": "",
            "receiver_service_config": {},
            "receiver_service_name": "",
            "receiver_inbox_email": "",
            "timeout": 30,
            "max_retries": 3,
            "proxy_url": None,
        }
        self.config = {**default_config, **raw_config}
        self.config["base_url"] = str(self.config.get("base_url") or "").rstrip("/")
        self.config["duck_api_base_url"] = str(self.config.get("duck_api_base_url") or "https://quack.duckduckgo.com").rstrip("/")
        self.config["mode"] = self._mode

        # custom_api 模式沿用历史必填校验
        if self._mode == "custom_api":
            missing_keys = []
            if not self.config.get("base_url"):
                missing_keys.append("base_url")
            if not parse_domain_list(self.config.get("default_domain") or self.config.get("domain")):
                missing_keys.append("default_domain")
            if missing_keys:
                raise ValueError(f"缺少必需配置: {missing_keys}")

        self._domains = self._resolve_domains(self.config) if self._mode == "custom_api" else []
        if self._domains:
            self.config["default_domain"] = ",".join(self._domains)

        http_config = RequestConfig(
            timeout=self.config["timeout"],
            max_retries=self.config["max_retries"],
        )
        self.http_client = HTTPClient(
            proxy_url=self.config.get("proxy_url"),
            config=http_config,
        )

        self._accounts_by_id: Dict[str, Dict[str, Any]] = {}
        self._accounts_by_email: Dict[str, Dict[str, Any]] = {}
        self._receiver_service = self._build_receiver_service()

    def _build_receiver_service(self):
        receiver_type_raw = str(self.config.get("receiver_service_type") or "").strip().lower()
        if not receiver_type_raw:
            return None
        try:
            receiver_type = EmailServiceType(receiver_type_raw)
        except Exception:
            logger.warning("DuckMail 收件后端类型无效，已忽略: %s", receiver_type_raw)
            return None
        if receiver_type == EmailServiceType.DUCK_MAIL:
            logger.warning("DuckMail 收件后端不能再选择 DuckMail，已忽略")
            return None

        receiver_config = self.config.get("receiver_service_config") or {}
        if not isinstance(receiver_config, dict):
            receiver_config = {}
        receiver_config = dict(receiver_config)

        receiver_inbox_email = str(self.config.get("receiver_inbox_email") or "").strip()
        # 对 CloudMail/TempMail 等后端统一注入固定收件箱配置
        if receiver_inbox_email:
            receiver_config.setdefault("inbox_email", receiver_inbox_email)

        try:
            return EmailServiceFactory.create(
                receiver_type,
                receiver_config,
                name=str(self.config.get("receiver_service_name") or f"{self.name}-receiver"),
            )
        except Exception as exc:
            logger.warning("DuckMail 收件后端初始化失败，已忽略: %s", exc)
            return None

    def _make_duck_official_request(
        self,
        method: str,
        path: str,
        token: Optional[str] = None,
        cookie: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        url = f"{self.config['duck_api_base_url']}{path}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
        }
        extra_headers = kwargs.pop("headers", None)
        if isinstance(extra_headers, dict):
            headers.update(extra_headers)

        normalized_token = self._normalize_bearer_token(token)
        if normalized_token:
            headers["Authorization"] = f"Bearer {normalized_token}"
        if cookie:
            headers["Cookie"] = cookie

        try:
            response = self.http_client.request(method, url, headers=headers, **kwargs)
            if response.status_code >= 400:
                detail = response.text[:300]
                raise EmailServiceError(f"Duck 官方接口失败: {response.status_code} - {detail}")
            try:
                return response.json()
            except Exception:
                return {"raw_response": response.text}
        except Exception as e:
            self.update_status(False, e)
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"Duck 官方请求失败: {method} {path} - {e}")

    @staticmethod
    def _normalize_bearer_token(token: Optional[str]) -> str:
        raw = str(token or "").strip()
        if not raw:
            return ""
        if raw.lower().startswith("bearer "):
            return raw[7:].strip()
        return raw

    def _resolve_duck_official_token(self) -> str:
        def _extract_token_from_dashboard(payload: Dict[str, Any]) -> str:
            if isinstance(payload, dict):
                return str(
                    payload.get("access_token")
                    or payload.get("token")
                    or (payload.get("data") or {}).get("access_token")
                    or ""
                ).strip()
            return ""

        token = self._normalize_bearer_token(
            self.config.get("duck_api_token")
            or self.config.get("api_key")
            or self.config.get("token")
            or ""
        )
        cookie = str(self.config.get("duck_cookie") or "").strip()

        # token 优先：有 token 时即允许继续使用；cookie 仅用于可选刷新
        if token:
            if not cookie:
                return token
            try:
                self._make_duck_official_request(
                    "GET",
                    "/api/email/dashboard",
                    token=token,
                    cookie=cookie,
                )
                return token
            except Exception as exc:
                text = str(exc).lower()
                if "invalid_token" in text or "401" in text:
                    logger.info("Duck token 失效，尝试通过 cookie 刷新 token")
                    try:
                        dashboard = self._make_duck_official_request(
                            "GET",
                            "/api/email/dashboard",
                            cookie=cookie,
                        )
                        refreshed = _extract_token_from_dashboard(dashboard)
                        if refreshed:
                            self.config["duck_api_token"] = refreshed
                            return refreshed
                    except Exception as refresh_exc:
                        logger.warning("Duck cookie 刷新 token 失败，回退继续使用现有 token: %s", refresh_exc)
                else:
                    logger.warning("Duck token 校验失败，回退继续使用现有 token: %s", exc)
                return token

        if not cookie:
            raise EmailServiceError("Duck 官方模式缺少 duck_api_token 或 duck_cookie")

        dashboard = self._make_duck_official_request(
            "GET",
            "/api/email/dashboard",
            cookie=cookie,
        )
        token = _extract_token_from_dashboard(dashboard)
        if not token:
            raise EmailServiceError("无法从 Duck dashboard 响应中提取 access_token")
        # 刷新后回写，减少后续 invalid_token 触发概率
        self.config["duck_api_token"] = token
        return token

    def _extract_official_alias(self, payload: Dict[str, Any]) -> str:
        candidates: List[str] = []
        alias_domain = str(self.config.get("duck_alias_domain") or "duck.com").strip().lower().lstrip("@")
        if not alias_domain:
            alias_domain = "duck.com"

        def _normalize_candidate(value: Any) -> str:
            text = str(value or "").strip().lower()
            if not text:
                return ""
            if "@" in text:
                return text
            # Duck 官方有时仅返回 local-part（不带域名）
            if re.fullmatch(r"[a-z0-9][a-z0-9._%+\-]{1,120}", text):
                return f"{text}@{alias_domain}"
            return ""

        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict):
                for key in ("address", "email", "alias"):
                    value = data.get(key)
                    if value:
                        candidates.append(str(value))
            for key in ("address", "email", "alias"):
                value = payload.get(key)
                if value:
                    candidates.append(str(value))
            raw = str(payload.get("raw_response") or "")
            if raw:
                candidates.extend(re.findall(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", raw, re.I))
                # 兼容 raw_response 仅包含 address local-part 的情况
                candidates.extend(re.findall(r'"address"\s*:\s*"([a-z0-9][a-z0-9._%+\-]{1,120})"', raw, re.I))

        for item in candidates:
            email = _normalize_candidate(item)
            if email:
                return email
        return ""

    def _create_email_duck_official(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        request_config = {**self.config, **(config or {})}
        token = self._resolve_duck_official_token()
        cookie = str(request_config.get("duck_cookie") or self.config.get("duck_cookie") or "").strip() or None

        payload = {}
        domain_hint = str(request_config.get("duck_address_domain") or "").strip()
        if domain_hint:
            payload["domain"] = domain_hint

        try:
            create_resp = self._make_duck_official_request(
                "POST",
                "/api/email/addresses",
                token=token,
                cookie=cookie,
                json=payload if payload else None,
            )
        except Exception:
            # 兼容部分服务端不接受 body 的情况
            create_resp = self._make_duck_official_request(
                "POST",
                "/api/email/addresses",
                token=token,
                cookie=cookie,
            )

        alias_email = self._extract_official_alias(create_resp)
        if not alias_email:
            raise EmailServiceError("Duck 官方模式生成私有地址失败：响应中未包含地址")

        email_info = {
            "email": alias_email,
            "service_id": alias_email,
            "id": alias_email,
            "account_id": alias_email,
            "created_at": time.time(),
            "duck_mode": "duck_official",
            "receiver_inbox_email": str(request_config.get("receiver_inbox_email") or "").strip(),
            "raw_account": create_resp,
        }
        self._cache_account(email_info)
        self.update_status(True)
        return email_info

    def _get_verification_code_via_receiver(
        self,
        email: str,
        email_id: Optional[str] = None,
        timeout: int = 120,
        pattern: str = OTP_CODE_PATTERN,
        otp_sent_at: Optional[float] = None,
        exclude_codes: Optional[List[str]] = None,
    ) -> Optional[str]:
        if not self._receiver_service:
            logger.warning("Duck 官方模式未配置收件后端，无法获取验证码")
            return None

        # Duck 官方链路拆分为两层：
        # 1) query_email: 后端实际拉取的固定收件箱（如 abc@qq.com）
        # 2) receiver_alias_email: 目标 Duck 临时别名（用于收件人过滤）
        receiver_inbox_email = str(self.config.get("receiver_inbox_email") or "").strip()
        query_email = receiver_inbox_email or email
        receiver_alias_email = str(email or "").strip().lower()

        receiver_config = getattr(self._receiver_service, "config", None)
        old_alias_email = None
        old_alias_filter = None
        old_alias_email_exists = False
        old_alias_filter_exists = False
        if isinstance(receiver_config, dict):
            old_alias_email_exists = "receiver_alias_email" in receiver_config
            old_alias_filter_exists = "receiver_alias_filter" in receiver_config
            old_alias_email = receiver_config.get("receiver_alias_email")
            old_alias_filter = receiver_config.get("receiver_alias_filter")
            receiver_config["receiver_alias_email"] = receiver_alias_email
            receiver_config.setdefault("receiver_alias_filter", True)

        kwargs = {
            "email": query_email,
            "email_id": email_id,
            "timeout": timeout,
            "pattern": pattern,
            "otp_sent_at": otp_sent_at,
        }
        try:
            params = inspect.signature(self._receiver_service.get_verification_code).parameters
        except Exception:
            params = {}
        if "exclude_codes" in params:
            kwargs["exclude_codes"] = exclude_codes or []

        try:
            code = self._receiver_service.get_verification_code(**kwargs)
            if code:
                self.update_status(True)
            return code
        except Exception as exc:
            logger.warning("Duck 收件后端获取验证码失败: %s", exc)
            self.update_status(False, exc)
            return None
        finally:
            if isinstance(receiver_config, dict):
                if old_alias_email_exists:
                    receiver_config["receiver_alias_email"] = old_alias_email
                else:
                    receiver_config.pop("receiver_alias_email", None)

                if old_alias_filter_exists:
                    receiver_config["receiver_alias_filter"] = old_alias_filter
                else:
                    receiver_config.pop("receiver_alias_filter", None)

    def _resolve_domains(self, config: Dict[str, Any]) -> List[str]:
        domains = parse_domain_list(config.get("domain"))
        if domains:
            return domains
        return parse_domain_list(config.get("default_domain"))

    def _build_domain_rr_key(self, domains: List[str]) -> str:
        base_url = str(self.config.get("base_url") or "").strip().lower()
        return f"duck_mail|{self.name}|{base_url}|{','.join(domains)}"

    def _build_headers(
        self,
        token: Optional[str] = None,
        use_api_key: bool = False,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        auth_token = token
        if not auth_token and use_api_key and self.config.get("api_key"):
            auth_token = self.config["api_key"]

        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        if extra_headers:
            headers.update(extra_headers)

        return headers

    def _make_request(
        self,
        method: str,
        path: str,
        token: Optional[str] = None,
        use_api_key: bool = False,
        **kwargs,
    ) -> Dict[str, Any]:
        url = f"{self.config['base_url']}{path}"
        kwargs["headers"] = self._build_headers(
            token=token,
            use_api_key=use_api_key,
            extra_headers=kwargs.get("headers"),
        )

        try:
            response = self.http_client.request(method, url, **kwargs)
            if response.status_code >= 400:
                error_message = f"API 请求失败: {response.status_code}"
                try:
                    error_payload = response.json()
                    error_message = f"{error_message} - {error_payload}"
                except Exception:
                    error_message = f"{error_message} - {response.text[:200]}"
                raise EmailServiceError(error_message)

            try:
                return response.json()
            except Exception:
                return {"raw_response": response.text}
        except Exception as e:
            self.update_status(False, e)
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"请求失败: {method} {path} - {e}")

    def _generate_local_part(self) -> str:
        first = random.choice(string.ascii_lowercase)
        rest = "".join(random.choices(string.ascii_lowercase + string.digits, k=7))
        return f"{first}{rest}"

    def _generate_password(self) -> str:
        length = max(6, int(self.config.get("password_length") or 12))
        alphabet = string.ascii_letters + string.digits
        return "".join(random.choices(alphabet, k=length))

    def _cache_account(self, account_info: Dict[str, Any]) -> None:
        account_id = str(account_info.get("account_id") or account_info.get("service_id") or "").strip()
        email = str(account_info.get("email") or "").strip().lower()

        if account_id:
            self._accounts_by_id[account_id] = account_info
        if email:
            self._accounts_by_email[email] = account_info

    def _get_account_info(self, email: Optional[str] = None, email_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if email_id:
            cached = self._accounts_by_id.get(str(email_id))
            if cached:
                return cached

        if email:
            cached = self._accounts_by_email.get(str(email).strip().lower())
            if cached:
                return cached

        return None

    def _strip_html(self, html_content: Any) -> str:
        if isinstance(html_content, list):
            html_content = "\n".join(str(item) for item in html_content if item)
        text = str(html_content or "")
        return unescape(re.sub(r"<[^>]+>", " ", text))

    def _parse_message_time(self, value: Optional[str]) -> Optional[float]:
        if not value:
            return None
        try:
            normalized = value.replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).astimezone(timezone.utc).timestamp()
        except Exception:
            return None

    def _message_search_text(self, summary: Dict[str, Any], detail: Dict[str, Any]) -> str:
        sender = summary.get("from") or detail.get("from") or {}
        if isinstance(sender, dict):
            sender_text = " ".join(
                str(sender.get(key) or "") for key in ("name", "address")
            ).strip()
        else:
            sender_text = str(sender)

        subject = str(summary.get("subject") or detail.get("subject") or "")
        text_body = str(detail.get("text") or "")
        html_body = self._strip_html(detail.get("html"))
        return "\n".join(part for part in [sender_text, subject, text_body, html_body] if part).strip()

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        if self._mode == "duck_official":
            return self._create_email_duck_official(config)

        request_config = {**self.config, **(config or {})}
        local_part = str(request_config.get("name") or self._generate_local_part()).strip()
        domains = self._resolve_domains(request_config) or self._domains
        domain = pick_domain(
            domains,
            strategy=request_config.get("domain_strategy"),
            rr_key=self._build_domain_rr_key(domains),
        )
        address = f"{local_part}@{domain}"
        password = self._generate_password()

        payload: Dict[str, Any] = {
            "address": address,
            "password": password,
        }

        expires_in = request_config.get("expiresIn", request_config.get("expires_in", self.config.get("expires_in")))
        if expires_in is not None:
            payload["expiresIn"] = expires_in

        account_response = self._make_request(
            "POST",
            "/accounts",
            json=payload,
            use_api_key=bool(self.config.get("api_key")),
        )
        token_response = self._make_request(
            "POST",
            "/token",
            json={
                "address": account_response.get("address", address),
                "password": password,
            },
        )

        account_id = str(account_response.get("id") or token_response.get("id") or "").strip()
        resolved_address = str(account_response.get("address") or address).strip()
        token = str(token_response.get("token") or "").strip()

        if not account_id or not resolved_address or not token:
            raise EmailServiceError("DuckMail 返回数据不完整")

        email_info = {
            "email": resolved_address,
            "service_id": account_id,
            "id": account_id,
            "account_id": account_id,
            "token": token,
            "password": password,
            "created_at": time.time(),
            "raw_account": account_response,
        }

        self._cache_account(email_info)
        self.update_status(True)
        return email_info

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 120,
        pattern: str = OTP_CODE_PATTERN,
        otp_sent_at: Optional[float] = None,
        exclude_codes: Optional[List[str]] = None,
    ) -> Optional[str]:
        if self._mode == "duck_official":
            return self._get_verification_code_via_receiver(
                email=email,
                email_id=email_id,
                timeout=timeout,
                pattern=pattern,
                otp_sent_at=otp_sent_at,
                exclude_codes=exclude_codes,
            )

        account_info = self._get_account_info(email=email, email_id=email_id)
        if not account_info:
            logger.warning(f"DuckMail 未找到邮箱缓存: {email}, {email_id}")
            return None

        token = account_info.get("token")
        if not token:
            logger.warning(f"DuckMail 邮箱缺少访问 token: {email}")
            return None

        start_time = time.time()
        seen_message_ids = set()

        while time.time() - start_time < timeout:
            try:
                response = self._make_request(
                    "GET",
                    "/messages",
                    token=token,
                    params={"page": 1},
                )
                messages = response.get("hydra:member", [])

                for message in messages:
                    message_id = str(message.get("id") or "").strip()
                    if not message_id or message_id in seen_message_ids:
                        continue

                    created_at = self._parse_message_time(message.get("createdAt"))
                    if otp_sent_at and created_at and created_at + 1 < otp_sent_at:
                        continue

                    seen_message_ids.add(message_id)
                    detail = self._make_request(
                        "GET",
                        f"/messages/{message_id}",
                        token=token,
                    )

                    content = self._message_search_text(message, detail)
                    if "openai" not in content.lower():
                        continue

                    match = re.search(pattern, content)
                    if match:
                        self.update_status(True)
                        return match.group(1)
            except Exception as e:
                logger.debug(f"DuckMail 轮询验证码失败: {e}")

            time.sleep(3)

        return None

    def list_emails(self, **kwargs) -> List[Dict[str, Any]]:
        return list(self._accounts_by_email.values())

    def delete_email(self, email_id: str) -> bool:
        if self._mode == "duck_official":
            # 官方私有地址通常通过网页管理，不在这里做删除；仅清理本地缓存
            account_info = self._get_account_info(email_id=email_id) or self._get_account_info(email=email_id)
            if not account_info:
                return False
            self._accounts_by_id.pop(str(account_info.get("account_id") or account_info.get("service_id") or ""), None)
            self._accounts_by_email.pop(str(account_info.get("email") or "").lower(), None)
            return True

        account_info = self._get_account_info(email_id=email_id) or self._get_account_info(email=email_id)
        if not account_info:
            return False

        token = account_info.get("token")
        account_id = account_info.get("account_id") or account_info.get("service_id")
        if not token or not account_id:
            return False

        try:
            self._make_request(
                "DELETE",
                f"/accounts/{account_id}",
                token=token,
            )
            self._accounts_by_id.pop(str(account_id), None)
            self._accounts_by_email.pop(str(account_info.get("email") or "").lower(), None)
            self.update_status(True)
            return True
        except Exception as e:
            logger.warning(f"DuckMail 删除邮箱失败: {e}")
            self.update_status(False, e)
            return False

    def check_health(self) -> bool:
        if self._mode == "duck_official":
            try:
                token = self._resolve_duck_official_token()
                cookie = str(self.config.get("duck_cookie") or "").strip() or None
                if cookie:
                    # 有 cookie 时优先走 dashboard 健康检查，失败则回退地址接口探测
                    try:
                        self._make_duck_official_request("GET", "/api/email/dashboard", token=token, cookie=cookie)
                    except Exception as dashboard_exc:
                        logger.warning("Duck dashboard 健康检查失败，回退地址接口探测: %s", dashboard_exc)
                        self._make_duck_official_request(
                            "POST",
                            "/api/email/addresses",
                            token=token,
                            json={},
                        )
                else:
                    # 对齐 v2.2 脚本：token-only 模式直接探测地址生成接口可用性
                    # 注意：该接口会实际生成一个 alias，这是 Duck 官方接口能力限制。
                    self._make_duck_official_request(
                        "POST",
                        "/api/email/addresses",
                        token=token,
                        json={},
                    )
                if self._receiver_service:
                    self._receiver_service.check_health()
                self.update_status(True)
                return True
            except Exception as e:
                logger.warning(f"Duck 官方模式健康检查失败: {e}")
                self.update_status(False, e)
                return False

        try:
            self._make_request(
                "GET",
                "/domains",
                params={"page": 1},
                use_api_key=bool(self.config.get("api_key")),
            )
            self.update_status(True)
            return True
        except Exception as e:
            logger.warning(f"DuckMail 健康检查失败: {e}")
            self.update_status(False, e)
            return False

    def get_email_messages(self, email_id: str, **kwargs) -> List[Dict[str, Any]]:
        if self._mode == "duck_official":
            if self._receiver_service and hasattr(self._receiver_service, "get_email_messages"):
                try:
                    return self._receiver_service.get_email_messages(email_id, **kwargs)  # type: ignore[attr-defined]
                except Exception:
                    return []
            return []

        account_info = self._get_account_info(email_id=email_id) or self._get_account_info(email=email_id)
        if not account_info or not account_info.get("token"):
            return []
        response = self._make_request(
            "GET",
            "/messages",
            token=account_info["token"],
            params={"page": kwargs.get("page", 1)},
        )
        return response.get("hydra:member", [])

    def get_message_detail(self, email_id: str, message_id: str) -> Optional[Dict[str, Any]]:
        if self._mode == "duck_official":
            if self._receiver_service and hasattr(self._receiver_service, "get_message_detail"):
                try:
                    return self._receiver_service.get_message_detail(email_id, message_id)  # type: ignore[attr-defined]
                except Exception:
                    return None
            return None

        account_info = self._get_account_info(email_id=email_id) or self._get_account_info(email=email_id)
        if not account_info or not account_info.get("token"):
            return None
        return self._make_request(
            "GET",
            f"/messages/{message_id}",
            token=account_info["token"],
        )

    def get_service_info(self) -> Dict[str, Any]:
        return {
            "service_type": self.service_type.value,
            "name": self.name,
            "mode": self._mode,
            "base_url": self.config.get("base_url", ""),
            "duck_api_base_url": self.config.get("duck_api_base_url", ""),
            "default_domain": self._domains[0] if self._domains else "",
            "domains": self._domains,
            "domain_strategy": self.config.get("domain_strategy", "round_robin"),
            "receiver_service_type": str(self.config.get("receiver_service_type") or ""),
            "receiver_service_name": str(self.config.get("receiver_service_name") or ""),
            "receiver_inbox_email": str(self.config.get("receiver_inbox_email") or ""),
            "cached_accounts": len(self._accounts_by_email),
            "status": self.status.value,
        }
