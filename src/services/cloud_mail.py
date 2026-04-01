"""
CloudMail 邮箱服务实现
"""

import logging
import re
import secrets
import time
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from .base import BaseEmailService, EmailServiceError, EmailServiceType
from ..core.http_client import HTTPClient, RequestConfig
from ..config.constants import OTP_CODE_PATTERN


logger = logging.getLogger(__name__)


class CloudMailService(BaseEmailService):
    """
    CloudMail 邮箱服务
    基于 CloudMail 的公开 API 轮询验证码
    """

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        super().__init__(EmailServiceType.CLOUD_MAIL, name)

        default_config = {
            "base_url": "",
            "api_token": "",
            "default_domain": "",
            "timeout": 30,
            "max_retries": 3,
            "poll_interval": 3,
            "time_tolerance": 43200,
            "otp_sent_time_skew_seconds": 12,
            "prefix": "oc",
            "token_bytes": 3,
            "page_size": 5,
            "auth_header": "Authorization",
            "auth_prefix": "",
            "proxy_url": None,
        }

        self.config = {**default_config, **(config or {})}
        self.config["base_url"] = str(self.config.get("base_url") or "").rstrip("/")

        missing_keys = []
        if not self.config.get("base_url"):
            missing_keys.append("base_url")
        if not (self.config.get("api_token") or self.config.get("token")):
            missing_keys.append("api_token")

        if missing_keys:
            raise ValueError(f"缺少必需配置: {missing_keys}")

        if not self._resolve_domain(self.config):
            raise ValueError("缺少邮箱域名")

        http_config = RequestConfig(
            timeout=self.config["timeout"],
            max_retries=self.config["max_retries"],
        )
        self.http_client = HTTPClient(
            proxy_url=self.config.get("proxy_url"),
            config=http_config,
        )

        self._email_cache: Dict[str, Dict[str, Any]] = {}
        self._last_code_cache: Dict[str, str] = {}
        self._last_message_id_cache: Dict[str, str] = {}

    def _resolve_domain(self, config: Dict[str, Any]) -> str:
        domain = (
            config.get("default_domain")
            or config.get("domain")
            or ""
        )
        return str(domain).strip().lstrip("@")

    def _sanitize_local_part(self, local_part: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9._-]", "", local_part or "")
        return safe.lower().strip(".")

    def _generate_local_part(self, config: Dict[str, Any]) -> str:
        prefix = self._sanitize_local_part(str(config.get("prefix") or "oc"))
        token_bytes = int(config.get("token_bytes") or 3)
        token_bytes = max(1, min(token_bytes, 16))
        stamp = int(time.time())
        rand = secrets.token_hex(token_bytes)
        return f"{prefix}{stamp}{rand}" if prefix else f"cm{stamp}{rand}"

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        token = self.config.get("api_token") or self.config.get("token")
        if token:
            header_name = str(self.config.get("auth_header") or "Authorization")
            prefix = str(self.config.get("auth_prefix") or "")
            headers[header_name] = f"{prefix}{token}" if prefix else str(token)
        return headers

    def _extract_message_timestamp(self, message: Dict[str, Any]) -> Optional[float]:
        candidates = [
            "createTime", "create_time",
            "createdAt", "created_at",
            "time", "timestamp",
        ]
        for key in candidates:
            if key not in message:
                continue
            value = message.get(key)
            ts = self._parse_timestamp(value)
            if ts:
                return ts
        nested = message.get("data")
        if isinstance(nested, dict):
            for key in candidates:
                if key not in nested:
                    continue
                ts = self._parse_timestamp(nested.get(key))
                if ts:
                    return ts
        return None

    def _parse_timestamp(self, value: Any) -> Optional[float]:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            ts = float(value)
        else:
            text = str(value).strip()
            if not text:
                return None
            if text.isdigit():
                ts = float(text)
            else:
                try:
                    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        # CloudMail 的 createTime 常见为无时区字符串，按 UTC 解释避免错判旧邮件
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.timestamp()
                except Exception:
                    return None
        if ts > 10_000_000_000:
            ts = ts / 1000.0
        return ts

    def _extract_messages(self, payload: Any) -> List[Dict[str, Any]]:
        """从 API 响应中提取邮件列表，兼容多种字段结构。"""
        if payload is None:
            return []

        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]

        if not isinstance(payload, dict):
            return []

        # 常见结构：{ "data": [...] } 或 { "data": { "list": [...] } }
        data = payload.get("data", payload)

        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]

        if isinstance(data, dict):
            for key in ("list", "records", "rows", "items", "emails", "messages", "result", "data"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            # 可能直接返回单条邮件对象
            if any(k in data for k in ("subject", "text", "content", "html", "body")):
                return [data]

        return []

    def _extract_message_text(self, message: Dict[str, Any]) -> str:
        """提取邮件正文文本，兼容不同字段名。"""
        parts: List[str] = []

        def _strip_html(text: str) -> str:
            return re.sub(r"<[^>]+>", " ", text)

        def _append(value: Any) -> None:
            if value is None:
                return
            if isinstance(value, list):
                merged = " ".join(str(item) for item in value if item)
                if merged:
                    parts.append(_strip_html(merged) if ("<" in merged and ">" in merged) else merged)
            else:
                text = str(value).strip()
                if text:
                    parts.append(_strip_html(text) if ("<" in text and ">" in text) else text)

        for key in (
            "subject", "title", "text", "content", "html", "body",
            "textContent", "contentText", "mailText", "mailContent",
            "bodyText", "text_body", "mail_body",
            "source", "raw"
        ):
            value = message.get(key)
            if isinstance(value, dict):
                for nested_key in ("subject", "title", "text", "content", "html", "body", "mailText"):
                    _append(value.get(nested_key))
            else:
                _append(value)

        # 兼容嵌套结构
        for nested_key in ("data", "mail", "email", "detail", "message"):
            nested = message.get(nested_key)
            if isinstance(nested, dict):
                for key in ("subject", "title", "text", "content", "html", "body", "mailText"):
                    _append(nested.get(key))

        return " ".join(parts).strip()

    def _extract_message_id(self, message: Dict[str, Any]) -> str:
        """提取邮件唯一标识，避免重复消费旧邮件。"""
        id_candidates = ("emailId", "id", "mailId", "messageId", "msgId")
        for key in id_candidates:
            value = message.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
        nested = message.get("data")
        if isinstance(nested, dict):
            for key in id_candidates:
                value = nested.get(key)
                if value is not None and str(value).strip():
                    return str(value).strip()
        return ""

    def _extract_code_from_text(self, text: str, pattern: str) -> Optional[str]:
        """从文本中提取验证码，优先语义匹配。"""
        if not text:
            return None
        lowered = text.lower()
        semantic_pattern = r"(?:code\\s+is|verification code|temporary verification code|one-time code|验证码)\\s*[:：]?\\s*(\\d{6})"
        if "openai" in lowered or "chatgpt" in lowered or "verification code" in lowered or "验证码" in text:
            match = re.search(semantic_pattern, text, re.I)
            if match:
                return match.group(1)

        match = re.search(pattern, text)
        return match.group(1) if match else None

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """生成 CloudMail 邮箱地址（无需远端创建）。"""
        try:
            request_config = {**self.config, **(config or {})}
            domain = self._resolve_domain(request_config)
            if not domain:
                raise EmailServiceError("CloudMail 缺少邮箱域名")

            local_part = (
                request_config.get("local_part")
                or request_config.get("name")
                or self._generate_local_part(request_config)
            )
            local_part = self._sanitize_local_part(str(local_part))
            if not local_part:
                local_part = self._generate_local_part(request_config)

            email = f"{local_part}@{domain}"
            email_info = {
                "email": email,
                "service_id": email,
                "created_at": time.time(),
                "domain": domain,
            }
            self._email_cache[email] = email_info

            logger.info(f"成功生成 CloudMail 邮箱: {email}")
            self.update_status(True)
            return email_info

        except Exception as e:
            self.update_status(False, e)
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"生成 CloudMail 邮箱失败: {e}")

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 120,
        pattern: str = OTP_CODE_PATTERN,
        otp_sent_at: Optional[float] = None,
    ) -> Optional[str]:
        """轮询 CloudMail API 获取验证码。"""
        if not email:
            return None

        url = f"{self.config['base_url']}/api/public/emailList"
        headers = self._build_headers()
        payload = {
            "toEmail": email,
            "timeSort": "desc",
            "num": 1,
            "size": int(self.config.get("page_size") or 5),
        }

        start_time = time.time()
        poll_interval = max(1, int(self.config.get("poll_interval") or 3))

        while time.time() - start_time < timeout:
            try:
                response = self.http_client.post(url, headers=headers, json=payload)
                if response.status_code != 200:
                    logger.debug(f"CloudMail 响应异常: {response.status_code} {response.text[:200]}")
                    time.sleep(poll_interval)
                    continue

                data = response.json()
                messages = self._extract_messages(data)
                if not messages:
                    if not getattr(self, "_debug_dumped", False):
                        try:
                            snippet = json.dumps(data, ensure_ascii=False)[:500]
                        except Exception:
                            snippet = str(data)[:500]
                        logger.warning(f"CloudMail 未解析到邮件列表，响应片段: {snippet}")
                        self._debug_dumped = True
                    time.sleep(poll_interval)
                    continue

                found_code = None
                last_message_id = self._last_message_id_cache.get(email, "")
                last_code = self._last_code_cache.get(email, "")
                skew_seconds = int(self.config.get("otp_sent_time_skew_seconds") or 12)
                skew_seconds = max(0, min(skew_seconds, 60))
                cutoff_ts = (otp_sent_at - skew_seconds) if otp_sent_at else None
                candidates: List[Dict[str, Any]] = []
                for message in messages:
                    if not isinstance(message, dict):
                        continue
                    msg_id = self._extract_message_id(message)
                    msg_time = self._extract_message_timestamp(message)
                    if cutoff_ts is not None:
                        if msg_time is None:
                            # 在 OAuth 二次登录阶段必须严格按时间窗口取码，避免吞旧码
                            continue
                        if msg_time < cutoff_ts:
                            continue

                    content = self._extract_message_text(message)
                    code = self._extract_code_from_text(content, pattern)
                    if not code and not content:
                        # 兜底：在原始消息 JSON 中尝试语义提取
                        raw_blob = json.dumps(message, ensure_ascii=False)
                        code = self._extract_code_from_text(raw_blob, pattern)

                    if code:
                        candidates.append(
                            {
                                "code": code,
                                "msg_id": msg_id,
                                "msg_time": float(msg_time) if msg_time is not None else float("-inf"),
                            }
                        )

                if candidates:
                    candidates.sort(key=lambda item: item["msg_time"], reverse=True)
                    for candidate in candidates:
                        code = str(candidate.get("code") or "")
                        msg_id = str(candidate.get("msg_id") or "")
                        if msg_id and last_message_id and msg_id == last_message_id:
                            continue
                        if not msg_id and last_code and code == last_code:
                            continue
                        self._last_code_cache[email] = code
                        if msg_id:
                            self._last_message_id_cache[email] = msg_id
                        logger.info(f"CloudMail 获取验证码成功: {code}")
                        self.update_status(True)
                        found_code = code
                        break

                if found_code:
                    return found_code

                if messages and not getattr(self, "_debug_no_code_dumped", False):
                    sample = messages[0] if isinstance(messages[0], dict) else {}
                    try:
                        snippet = json.dumps(sample, ensure_ascii=False)[:400]
                    except Exception:
                        snippet = str(sample)[:400]
                    logger.warning(f"CloudMail 已获取邮件但未匹配验证码，示例片段: {snippet}")
                    self._debug_no_code_dumped = True

            except Exception as e:
                logger.debug(f"CloudMail 轮询失败: {e}")

            time.sleep(poll_interval)

        logger.warning(f"CloudMail 等待验证码超时: {email}")
        return None

    def list_emails(self, **kwargs) -> List[Dict[str, Any]]:
        """返回缓存邮箱列表。"""
        return list(self._email_cache.values())

    def delete_email(self, email_id: str) -> bool:
        """CloudMail 不支持删除邮箱，这里仅清理缓存。"""
        if not email_id:
            return False
        keys_to_remove = [
            email for email, info in self._email_cache.items()
            if info.get("service_id") == email_id or email == email_id
        ]
        for key in keys_to_remove:
            self._email_cache.pop(key, None)
        return bool(keys_to_remove)

    def check_health(self) -> bool:
        """检查 CloudMail 服务可用性。"""
        try:
            domain = self._resolve_domain(self.config)
            test_email = f"healthcheck@{domain}" if domain else "healthcheck@example.com"
            url = f"{self.config['base_url']}/api/public/emailList"
            payload = {
                "toEmail": test_email,
                "timeSort": "desc",
                "num": 1,
                "size": 1,
            }
            response = self.http_client.post(url, headers=self._build_headers(), json=payload)
            if response.status_code >= 500:
                self.update_status(False, EmailServiceError(f"状态码: {response.status_code}"))
                return False
            self.update_status(True)
            return True
        except Exception as e:
            logger.warning(f"CloudMail 健康检查失败: {e}")
            self.update_status(False, e)
            return False
