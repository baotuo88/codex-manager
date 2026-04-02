import asyncio
import json
import base64
import re
import time
import logging
import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime
from collections import deque
import threading
from urllib.parse import quote

from curl_cffi import requests as cffi_requests

from ..database.session import get_db
from ..database import crud
from ..config.settings import get_settings
from ..config.constants import EmailServiceType
from .upload.cpa_upload import _normalize_cpa_auth_files_url, _build_cpa_headers
from ..web.routes.registration import run_batch_registration
from .pending_oauth import process_pending_oauth_once, get_oauth_pending_overview

logger = logging.getLogger(__name__)

# 系统日志缓冲池（最多保留500条）
global_log_counter = 0
system_logs = deque(maxlen=500)

def append_system_log(level: str, msg: str):
    global global_log_counter
    global_log_counter += 1
    system_logs.append({"id": global_log_counter, "level": level, "msg": f"[系统自动任务] {msg}"})

DEFAULT_CLIPROXY_UA = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
KNOWN_CLIPROXY_ERROR_LABELS = {
    "usage_limit_reached": "周限额已耗尽",
    "account_deactivated": "账号已停用",
    "insufficient_quota": "额度不足",
    "invalid_api_key": "凭证无效",
    "unsupported_region": "地区不支持",
}
SUPPORTED_PLAN_TYPES = {"free", "plus", "team", "pro", "unknown", "all"}
SUPPORTED_RULE_TASKS = {"invalid", "quota"}
SUPPORTED_RULE_CONDITIONS = {"invalid_signal", "weekly_remaining_percent", "five_hour_remaining_percent"}
SUPPORTED_RULE_OPERATORS = {"lt", "lte", "gt", "gte", "eq", "neq"}
SUPPORTED_RULE_ACTIONS = {"remove", "disable", "enable"}
SUPPORTED_RULE_TARGET_STATUS = {"all", "enabled", "disabled"}


def _extract_cpa_error(response) -> str:
    error_msg = f"HTTP {response.status_code}"
    try:
        data = response.json()
        if isinstance(data, dict):
            error_msg = data.get("message", error_msg)
    except Exception:
        error_msg = f"{error_msg} - {response.text[:200]}"
    return error_msg


def _extract_cliproxy_account_id(item: dict) -> Optional[str]:
    for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
        val = item.get(key)
        if val:
            return str(val)
    id_token = item.get("id_token")
    if isinstance(id_token, dict):
        val = id_token.get("chatgpt_account_id")
        if val:
            return str(val)
    if isinstance(id_token, str):
        val = _extract_account_id_from_jwt(id_token)
        if val:
            return val
    return None


def _extract_account_id_from_jwt(token: str) -> Optional[str]:
    """从 JWT 中解析 chatgpt_account_id（兼容 Session 提取的 token）。"""
    if not token or token.count(".") < 2:
        return None
    payload_b64 = token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        claims = json.loads(payload.decode("utf-8"))
        auth_claims = claims.get("https://api.openai.com/auth") or {}
        account_id = (
            auth_claims.get("chatgpt_account_id")
            or claims.get("chatgpt_account_id")
            or claims.get("account_id")
        )
        return str(account_id or "").strip() or None
    except Exception:
        return None


def _coerce_status_code(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
    return None


def _infer_status_code_from_text(text: str) -> Optional[int]:
    if not text:
        return None
    lower = text.lower()
    if (
        "token_revoked" in lower
        or "token_invalidated" in lower
        or "invalidated oauth token" in lower
        or "authentication token has been invalidated" in lower
        or "token has been invalidated" in lower
    ):
        return 401
    if "unauthorized" in lower:
        return 401
    if "forbidden" in lower:
        return 403
    match = re.search(r"\b(401|403)\b", lower)
    if match:
        return int(match.group(1))
    return None


def _maybe_parse_json_text(text: str) -> Optional[Any]:
    if not text:
        return None
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except Exception:
        return None


def _extract_cliproxy_status_code(item: Any) -> Optional[int]:
    if not isinstance(item, dict):
        return None

    def _check_value(value: Any) -> Optional[int]:
        code = _coerce_status_code(value)
        if code is not None:
            return code
        if isinstance(value, str):
            inferred = _infer_status_code_from_text(value)
            if inferred is not None:
                return inferred
            parsed = _maybe_parse_json_text(value)
            if isinstance(parsed, dict):
                return _extract_cliproxy_status_code(parsed)
        return None

    for key in (
        "status_code",
        "statusCode",
        "http_status",
        "httpStatus",
        "last_status_code",
        "lastStatusCode",
        "last_http_status",
        "lastHttpStatus",
        "status",
        "http_code",
        "httpCode",
        "code",
    ):
        code = _check_value(item.get(key))
        if code is not None:
            return code

    for key in (
        "status_message",
        "statusMessage",
        "last_status",
        "lastStatus",
        "error",
        "last_error",
        "lastError",
        "error_message",
        "errorMessage",
        "message",
        "reason",
    ):
        nested = item.get(key)
        if isinstance(nested, str):
            inferred = _infer_status_code_from_text(nested)
            if inferred is not None:
                return inferred
            parsed = _maybe_parse_json_text(nested)
            if isinstance(parsed, dict):
                nested = parsed
        if isinstance(nested, dict):
            for inner_key in (
                "status_code",
                "statusCode",
                "http_status",
                "httpStatus",
                "status",
                "http_code",
                "httpCode",
                "code",
                "message",
                "error",
                "reason",
            ):
                code = _check_value(nested.get(inner_key))
                if code is not None:
                    return code
    return None


def _extract_cpa_provider_value(payload: Any) -> Optional[str]:
    if isinstance(payload, dict):
        for key in ("provider", "type"):
            value = str(payload.get(key) or "").strip().lower()
            if value:
                return value

        for key in ("metadata", "auth", "auth_file", "data", "payload", "content", "json"):
            nested = payload.get(key)
            provider = _extract_cpa_provider_value(_decode_possible_json_payload(nested))
            if provider:
                return provider

    if isinstance(payload, list):
        for item in payload:
            provider = _extract_cpa_provider_value(_decode_possible_json_payload(item))
            if provider:
                return provider

    if isinstance(payload, str):
        return _extract_cpa_provider_value(_decode_possible_json_payload(payload))

    return None


def _parse_auto_register_email_pool(raw: str) -> List[tuple[str, Optional[int]]]:
    """解析自动注册邮箱服务列表（支持逗号分隔）。"""
    if not raw:
        return []
    items = [item.strip() for item in str(raw).replace(";", ",").split(",") if item.strip()]
    pool: List[tuple[str, Optional[int]]] = []
    for item in items:
        if ":" in item:
            svc_type, svc_id = item.split(":", 1)
        else:
            svc_type, svc_id = item, ""
        svc_type = svc_type.strip()
        if not svc_type:
            continue
        try:
            EmailServiceType(svc_type)
        except Exception:
            continue
        svc_id = (svc_id or "").strip()
        parsed_id: Optional[int] = None
        if svc_id and svc_id not in {"default", "all"}:
            try:
                parsed_id = int(svc_id)
            except Exception:
                parsed_id = None
        pool.append((svc_type, parsed_id))
    return pool


def _is_cpa_codex_auth_file(item: dict) -> bool:
    if not isinstance(item, dict):
        return False
    return _extract_cpa_provider_value(item) == "codex"


def fetch_cliproxy_auth_files(api_url: str, api_token: str) -> tuple[List[dict], int, int]:
    url = _normalize_cpa_auth_files_url(api_url)
    resp = cffi_requests.get(url, headers=_build_cpa_headers(api_token), timeout=30, impersonate="chrome110")
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        return [], 0, 0
    files = data.get("files")
    if not isinstance(files, list):
        return [], 0, 0

    normalized_files = [item for item in files if isinstance(item, dict)]
    total_count = len(normalized_files)

    codex_files = [item for item in normalized_files if _is_cpa_codex_auth_file(item)]
    skipped_count = total_count - len(codex_files)
    return codex_files, total_count, skipped_count


def _decode_possible_json_payload(payload: Any) -> Any:
    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return payload
        try:
            return json.loads(text)
        except Exception:
            return payload
    return payload


def _extract_remaining_percent(window_info: Any) -> Optional[float]:
    if not isinstance(window_info, dict):
        return None

    remaining_percent = window_info.get("remaining_percent")
    if isinstance(remaining_percent, (int, float)):
        return max(0.0, min(100.0, float(remaining_percent)))

    used_percent = window_info.get("used_percent")
    if isinstance(used_percent, (int, float)):
        return max(0.0, min(100.0, 100.0 - float(used_percent)))

    return None


def _format_percent(value: float) -> str:
    normalized = round(float(value), 2)
    if normalized.is_integer():
        return str(int(normalized))
    return f"{normalized:.2f}".rstrip("0").rstrip(".")


def _format_known_cliproxy_error(error_type: str) -> str:
    label = KNOWN_CLIPROXY_ERROR_LABELS.get(error_type)
    if label:
        return f"{label} ({error_type})"
    return f"错误类型: {error_type}"


def _is_usage_limit_reached_text(text: Any) -> bool:
    lower = str(text or "").strip().lower()
    if not lower:
        return False
    return (
        "usage_limit_reached" in lower
        or "the usage limit has been reached" in lower
        or "usage limit has been reached" in lower
        or "周限额已耗尽" in lower
        or "额度已耗尽" in lower
    )


def _payload_has_usage_limit_reached(payload: Any) -> bool:
    data = _decode_possible_json_payload(payload)
    if isinstance(data, str):
        return _is_usage_limit_reached_text(data)
    try:
        raw = json.dumps(data, ensure_ascii=False)
    except Exception:
        raw = str(data)
    return _is_usage_limit_reached_text(raw)


def _extract_rate_limit_reason(
    rate_info: Any,
    key: str,
    min_remaining_weekly_percent: int = 0,
) -> Optional[str]:
    if not isinstance(rate_info, dict):
        return None
    allowed = rate_info.get("allowed")
    limit_reached = rate_info.get("limit_reached")
    if allowed is False or limit_reached is True:
        label_map = {
            "rate_limit": "周限额已耗尽",
            "code_review_rate_limit": "代码审查周限额已耗尽",
        }
        label = label_map.get(key, f"{key} 已耗尽")
        return f"{label}（allowed={allowed}, limit_reached={limit_reached}）"

    if key == "rate_limit" and min_remaining_weekly_percent > 0:
        remaining_percent = _extract_remaining_percent(rate_info.get("primary_window"))
        if remaining_percent is not None and remaining_percent < min_remaining_weekly_percent:
            return (
                f"周限额剩余 {_format_percent(remaining_percent)}%，"
                f"低于阈值 {min_remaining_weekly_percent}%"
            )
    return None


def _extract_cliproxy_failure_reason(
    payload: Any,
    min_remaining_weekly_percent: int = 0,
) -> Optional[str]:
    data = _decode_possible_json_payload(payload)

    if isinstance(data, str):
        lower_text = data.lower()
        if _is_usage_limit_reached_text(lower_text):
            return _format_known_cliproxy_error("usage_limit_reached")
        for keyword in (
            "account_deactivated",
            "insufficient_quota",
            "invalid_api_key",
            "unsupported_region",
        ):
            if keyword in lower_text:
                return _format_known_cliproxy_error(keyword)
        inferred_status = _infer_status_code_from_text(data)
        if inferred_status in (401, 403):
            return f"status_code={inferred_status}"
        return None

    if not isinstance(data, dict):
        return None

    error = data.get("error")
    if isinstance(error, dict):
        err_type = error.get("type")
        if err_type:
            return _format_known_cliproxy_error(err_type)
        message = error.get("message")
        if message:
            if _is_usage_limit_reached_text(message):
                return _format_known_cliproxy_error("usage_limit_reached")
            return str(message)

    for key in ("rate_limit", "code_review_rate_limit"):
        min_remaining_percent = min_remaining_weekly_percent if key == "rate_limit" else 0
        reason = _extract_rate_limit_reason(
            data.get(key),
            key,
            min_remaining_percent,
        )
        if reason:
            return reason

    additional_rate_limits = data.get("additional_rate_limits")
    if isinstance(additional_rate_limits, list):
        for index, rate_info in enumerate(additional_rate_limits):
            reason = _extract_rate_limit_reason(
                rate_info,
                f"additional_rate_limits[{index}]",
                0,
            )
            if reason:
                return reason
    elif isinstance(additional_rate_limits, dict):
        for key, rate_info in additional_rate_limits.items():
            reason = _extract_rate_limit_reason(
                rate_info,
                f"additional_rate_limits.{key}",
                0,
            )
            if reason:
                return reason

    for key in ("data", "body", "response", "text", "content", "status_message"):
        reason = _extract_cliproxy_failure_reason(
            data.get(key),
            min_remaining_weekly_percent,
        )
        if reason:
            return reason

    data_str = json.dumps(data, ensure_ascii=False)
    lower_data_str = data_str.lower()
    if _is_usage_limit_reached_text(lower_data_str):
        return _format_known_cliproxy_error("usage_limit_reached")
    for keyword in (
        "account_deactivated",
        "insufficient_quota",
        "invalid_api_key",
        "unsupported_region",
    ):
        if keyword in lower_data_str:
            return _format_known_cliproxy_error(keyword)

    inferred_status = _infer_status_code_from_text(data_str)
    if inferred_status in (401, 403):
        return f"status_code={inferred_status}"

    return None


def _extract_cliproxy_item_failure_reason(
    item: dict,
    min_remaining_weekly_percent: int = 0,
) -> Optional[str]:
    status_message = item.get("status_message")
    reason = _extract_cliproxy_failure_reason(
        status_message,
        min_remaining_weekly_percent,
    )
    if item.get("unavailable") is True:
        return f"unavailable ({reason or item.get('status') or 'unknown'})"

    if not reason and isinstance(status_message, str):
        inferred_status = _infer_status_code_from_text(status_message)
        if inferred_status in (401, 403):
            reason = f"status_code={inferred_status}"

    status = str(item.get("status") or "").strip().lower()
    if status in {"invalid", "disabled"}:
        return f"status={status}"

    return reason


def _extract_cliproxy_panel_direct_reason(item: dict) -> Optional[str]:
    """面板直接剔除使用的明确错误（401/403 或 usage_limit_reached）。"""
    status_code = _extract_cliproxy_status_code(item)
    if status_code in (401, 403):
        return f"status_code={status_code}"

    reason = _extract_cliproxy_failure_reason(item, 0)
    inferred_status = _infer_status_code_from_text(str(reason or ""))
    if inferred_status in (401, 403):
        return f"status_code={inferred_status}"
    if reason and _is_usage_limit_reached_text(reason):
        return reason

    return None


def _describe_cliproxy_failure(msg: str) -> str:
    text = str(msg or "")
    if "低于阈值" in text:
        return "周限额低于阈值"
    if "周限额已耗尽" in text or _is_usage_limit_reached_text(text):
        return "周限额已耗尽"
    if "代码审查周限额已耗尽" in text:
        return "代码审查周限额已耗尽"
    return "失效"


def _normalize_plan_value(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    if not text:
        return "unknown"
    aliases = {
        "chatgpt_free": "free",
        "free_plan": "free",
        "chatgpt_plus": "plus",
        "plus_plan": "plus",
        "chatgpt_team": "team",
        "team_plan": "team",
        "chatgpt_pro": "pro",
        "pro_plan": "pro",
        "enterprise": "team",
    }
    text = aliases.get(text, text)
    if text in SUPPORTED_PLAN_TYPES:
        return text
    for plan in ("free", "plus", "team", "pro"):
        if plan in text:
            return plan
    return "unknown"


def _normalize_policy_rule(item: Any, idx: int) -> Optional[dict]:
    if not isinstance(item, dict):
        return None
    plans = item.get("plan_types") or item.get("plans") or []
    if not isinstance(plans, list):
        plans = []
    normalized_plans = []
    for plan in plans:
        normalized = _normalize_plan_value(plan)
        if normalized not in normalized_plans:
            normalized_plans.append(normalized)
    if not normalized_plans:
        normalized_plans = ["all"]

    task = str(item.get("task") or "invalid").strip().lower()
    if task not in SUPPORTED_RULE_TASKS:
        task = "invalid"

    condition = str(item.get("condition") or "invalid_signal").strip().lower()
    if condition not in SUPPORTED_RULE_CONDITIONS:
        condition = "invalid_signal"

    operator = str(item.get("operator") or "lt").strip().lower()
    if operator not in SUPPORTED_RULE_OPERATORS:
        operator = "lt"

    target_status = str(item.get("target_status") or "all").strip().lower()
    if target_status not in SUPPORTED_RULE_TARGET_STATUS:
        target_status = "all"

    action = str(item.get("action") or "remove").strip().lower()
    if action not in SUPPORTED_RULE_ACTIONS:
        action = "remove"

    try:
        threshold = float(item.get("threshold") or 0)
    except Exception:
        threshold = 0.0

    return {
        "id": str(item.get("id") or f"rule_{idx + 1}"),
        "name": str(item.get("name") or "").strip(),
        "enabled": bool(item.get("enabled", True)),
        "task": task,
        "condition": condition,
        "operator": operator,
        "threshold": threshold,
        "target_status": target_status,
        "action": action,
        "plan_types": normalized_plans,
        "fallback_to_weekly": bool(item.get("fallback_to_weekly", False)),
    }


def _build_legacy_policy_rules(settings) -> List[dict]:
    rules: List[dict] = [
        {
            "id": "legacy_invalid_remove",
            "name": "失效凭证默认剔除",
            "enabled": True,
            "task": "invalid",
            "condition": "invalid_signal",
            "operator": "lt",
            "threshold": 0.0,
            "target_status": "all",
            "action": "remove",
            "plan_types": ["all"],
            "fallback_to_weekly": False,
        }
    ]
    try:
        min_remaining = int(getattr(settings, "cpa_auto_check_min_remaining_weekly_percent", 0) or 0)
    except Exception:
        min_remaining = 0
    min_remaining = max(0, min(100, min_remaining))
    if min_remaining > 0:
        rules.append(
            {
                "id": "legacy_weekly_low_remove",
                "name": "周限额低于阈值剔除",
                "enabled": True,
                "task": "quota",
                "condition": "weekly_remaining_percent",
                "operator": "lt",
                "threshold": float(min_remaining),
                "target_status": "enabled",
                "action": "remove",
                "plan_types": ["all"],
                "fallback_to_weekly": False,
            }
        )
    return rules


def _load_cpa_policy_rules(settings) -> List[dict]:
    raw = getattr(settings, "cpa_auto_policy_rules", "[]")
    data = []
    if isinstance(raw, list):
        data = raw
    elif isinstance(raw, str):
        text = raw.strip()
        if text:
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    data = parsed
            except Exception:
                data = []

    normalized = []
    for idx, item in enumerate(data):
        rule = _normalize_policy_rule(item, idx)
        if rule:
            normalized.append(rule)

    if not normalized:
        normalized = _build_legacy_policy_rules(settings)
    return normalized


def _extract_item_status_for_rule(item: dict) -> str:
    enabled_flag = item.get("enabled")
    if isinstance(enabled_flag, bool):
        return "enabled" if enabled_flag else "disabled"

    status = str(item.get("status") or "").strip().lower()
    if status in {"disabled", "invalid", "inactive", "off"}:
        return "disabled"
    return "enabled"


def _extract_plan_type_from_payload(payload: Any) -> Optional[str]:
    data = _decode_possible_json_payload(payload)
    if isinstance(data, dict):
        plan_keys = (
            "plan",
            "plan_type",
            "planType",
            "subscription_plan",
            "subscription_type",
            "membership",
            "tier",
            "account_plan",
            "account_type",
            "chatgpt_plan",
        )
        for key in (
            *plan_keys,
        ):
            value = data.get(key)
            if value:
                return _normalize_plan_value(value)

        preferred_nested_keys = (
            "subscription",
            "metadata",
            "meta",
            "profile",
            "account",
            "auth",
            "payload",
            "json",
            "data",
            "error",
            "response",
            "body",
            "result",
            "details",
            "status_message",
        )
        for key in preferred_nested_keys:
            nested = _extract_plan_type_from_payload(data.get(key))
            if nested:
                return nested

        # 兜底扫描剩余嵌套字段（例如 error.plan_type），避免计划类型被漏掉。
        skip_keys = set(plan_keys) | set(preferred_nested_keys)
        for key, value in data.items():
            if key in skip_keys:
                continue
            if isinstance(value, (dict, list, str)):
                nested = _extract_plan_type_from_payload(value)
                if nested:
                    return nested
    elif isinstance(data, list):
        for entry in data:
            nested = _extract_plan_type_from_payload(entry)
            if nested:
                return nested
    return None


def _extract_plan_type_from_name(name: Any) -> Optional[str]:
    text = str(name or "").strip().lower()
    if not text:
        return None
    # 常见格式: xxx-team.json / xxx_plus_xxx / xxx.pro.xxx
    match = re.search(r"(?:^|[-_.@])(free|plus|team|pro|unknown)(?:[-_.@]|\.json$|$)", text)
    if match:
        return _normalize_plan_value(match.group(1))
    for plan in ("free", "plus", "team", "pro", "unknown"):
        if plan in text:
            return _normalize_plan_value(plan)
    return None


def _extract_item_plan_type(item: dict) -> str:
    for key in (
        "plan",
        "plan_type",
        "planType",
        "subscription_plan",
        "subscription_type",
        "tier",
        "membership",
        "account_plan",
        "account_type",
    ):
        value = item.get(key)
        if value:
            return _normalize_plan_value(value)

    payload = _extract_auth_payload_from_item(item)
    payload_plan = _extract_plan_type_from_payload(payload)
    if payload_plan:
        return payload_plan

    for key in ("name", "filename", "file_name", "auth_file_name"):
        name_plan = _extract_plan_type_from_name(item.get(key))
        if name_plan:
            return name_plan

    return "unknown"


def _is_rule_plan_match(rule: dict, plan_type: str) -> bool:
    plans = rule.get("plan_types") or ["all"]
    if "all" in plans:
        return True
    return plan_type in plans


def _is_rule_status_match(rule: dict, item_status: str) -> bool:
    target_status = rule.get("target_status", "all")
    if target_status == "all":
        return True
    return target_status == item_status


def _compare_threshold(value: float, operator: str, threshold: float) -> bool:
    if operator == "lt":
        return value < threshold
    if operator == "lte":
        return value <= threshold
    if operator == "gt":
        return value > threshold
    if operator == "gte":
        return value >= threshold
    if operator == "eq":
        return value == threshold
    if operator == "neq":
        return value != threshold
    return False


def _build_cliproxy_api_call_url(api_url: str) -> str:
    base_url = (api_url or "").strip().rstrip("/")
    if base_url.endswith("/v0/management"):
        return f"{base_url}/api-call"
    if base_url.endswith("/management"):
        return f"{base_url}/api-call"
    if base_url.endswith("/v0"):
        return f"{base_url}/management/api-call"
    if base_url.endswith("/auth-files"):
        return base_url.replace("/auth-files", "/api-call")
    return f"{base_url}/v0/management/api-call"


def _build_cliproxy_probe_payload(item: dict, settings) -> tuple[Optional[dict], Optional[str]]:
    auth_index = item.get("auth_index")
    if not auth_index:
        return None, "missing auth_index"

    account_id = _extract_cliproxy_account_id(item)
    call_header: dict = {
        "Authorization": "Bearer $TOKEN$",
        "Content-Type": "application/json",
        "User-Agent": DEFAULT_CLIPROXY_UA,
    }
    if account_id:
        call_header["Chatgpt-Account-Id"] = account_id

    test_url = settings.cpa_auto_check_test_url or "https://chatgpt.com/backend-api/wham/usage"
    test_model = settings.cpa_auto_check_test_model or "gpt-5.2-codex"
    method = "POST" if (test_model and "usage" not in test_url.lower()) else "GET"

    payload = {
        "authIndex": auth_index,
        "method": method,
        "url": test_url,
        "header": call_header,
    }
    if test_model:
        payload["body"] = {"model": test_model}
    return payload, None


def _collect_quota_windows(node: Any, path: str, windows: List[tuple[str, dict]]) -> None:
    if isinstance(node, dict):
        if any(key in node for key in ("remaining_percent", "used_percent")):
            windows.append((path, node))
        for key, value in node.items():
            next_path = f"{path}.{key}" if path else str(key)
            _collect_quota_windows(value, next_path, windows)
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            next_path = f"{path}[{idx}]"
            _collect_quota_windows(value, next_path, windows)


def _parse_window_hours(window: dict) -> Optional[float]:
    for key in ("window_hours", "duration_hours", "hours"):
        value = window.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    for key, scale in (("window_seconds", 3600.0), ("duration_seconds", 3600.0), ("window_minutes", 60.0), ("duration_minutes", 60.0)):
        value = window.get(key)
        if isinstance(value, (int, float)):
            return float(value) / scale
    return None


def _extract_quota_metrics(payload: Any) -> dict:
    data = _decode_possible_json_payload(payload)
    if _payload_has_usage_limit_reached(data):
        return {
            "weekly_remaining_percent": 0.0,
            "five_hour_remaining_percent": 0.0,
            "has_five_hour_limit": True,
        }
    if not isinstance(data, dict):
        return {
            "weekly_remaining_percent": None,
            "five_hour_remaining_percent": None,
            "has_five_hour_limit": False,
        }

    windows: List[tuple[str, dict]] = []
    _collect_quota_windows(data, "", windows)

    weekly_remaining: Optional[float] = None
    five_hour_remaining: Optional[float] = None
    has_five_hour_limit = False

    for path, window in windows:
        remaining = _extract_remaining_percent(window)
        if remaining is None:
            continue
        path_lower = path.lower()
        window_hours = _parse_window_hours(window)

        is_weekly = (
            any(token in path_lower for token in ("weekly", "week", "7d", "7_day", "168h", "primary_window"))
            or (window_hours is not None and 160.0 <= window_hours <= 176.0)
        )
        is_five_hour = (
            any(token in path_lower for token in ("5h", "5_hour", "5-hour", "five_hour", "short_window"))
            or (window_hours is not None and 4.5 <= window_hours <= 5.5)
        )

        if is_weekly and weekly_remaining is None:
            weekly_remaining = remaining
        if is_five_hour and five_hour_remaining is None:
            five_hour_remaining = remaining
            has_five_hour_limit = True

    return {
        "weekly_remaining_percent": weekly_remaining,
        "five_hour_remaining_percent": five_hour_remaining,
        "has_five_hour_limit": has_five_hour_limit,
    }


def _extract_auth_payload_from_item(item: dict) -> Optional[dict]:
    if not isinstance(item, dict):
        return None

    candidate_keys = (
        "payload",
        "json",
        "content",
        "auth",
        "auth_file",
        "data",
        "body",
        "status_message",
    )
    for key in candidate_keys:
        payload = _decode_possible_json_payload(item.get(key))
        if isinstance(payload, dict):
            if payload.get("type") == "codex" or payload.get("provider") == "codex":
                return dict(payload)
            if any(field in payload for field in ("access_token", "refresh_token", "id_token", "email")):
                return dict(payload)
            for nested_key in ("payload", "json", "auth", "auth_file", "data", "body"):
                nested = _decode_possible_json_payload(payload.get(nested_key))
                if isinstance(nested, dict) and any(field in nested for field in ("access_token", "refresh_token", "id_token", "email")):
                    return dict(nested)

    fallback = {}
    for key in ("email", "id_token", "access_token", "refresh_token", "account_id", "chatgpt_account_id", "chatgptAccountId", "user_agent", "headers"):
        if item.get(key) is not None:
            fallback[key] = item.get(key)
    if fallback:
        if "type" not in fallback:
            fallback["type"] = "codex"
        return fallback
    return None


def _set_auth_payload_enabled(payload: dict, enabled: bool) -> dict:
    updated = dict(payload or {})
    updated["enabled"] = bool(enabled)
    updated["disabled"] = not bool(enabled)
    updated["status"] = "enabled" if enabled else "disabled"
    meta = updated.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
    meta["scheduler_last_toggle_enabled"] = bool(enabled)
    meta["scheduler_last_toggle_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    updated["metadata"] = meta
    if "provider" not in updated and "type" in updated:
        updated["provider"] = updated.get("type")
    if "type" not in updated and "provider" in updated:
        updated["type"] = updated.get("provider")
    if not updated.get("type"):
        updated["type"] = "codex"
    return updated


def set_cliproxy_auth_file_enabled(item: dict, name: str, enabled: bool, api_url: str, api_token: str) -> tuple[bool, str]:
    if not name:
        return False, "missing name"

    auth_url = _normalize_cpa_auth_files_url(api_url)
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    toggle_payload = {"name": name, "enabled": enabled}
    toggle_attempts = [
        ("patch", auth_url, {"params": {"name": name}, "json": {"enabled": enabled}}),
        ("patch", f"{auth_url}/{quote(name)}", {"json": {"enabled": enabled}}),
        ("post", f"{auth_url}/status", {"json": toggle_payload}),
        ("post", f"{auth_url}/toggle", {"json": toggle_payload}),
    ]

    for method, url, kwargs in toggle_attempts:
        try:
            resp = cffi_requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                timeout=20,
                impersonate="chrome110",
                **kwargs,
            )
            if resp.status_code in (200, 201):
                return True, f"status_code={resp.status_code}"
        except Exception:
            continue

    payload = _extract_auth_payload_from_item(item)
    if not payload:
        return False, "no payload to update"
    updated_payload = _set_auth_payload_enabled(payload, enabled)

    raw_upload_url = f"{auth_url}?name={quote(name)}"
    resp = cffi_requests.post(
        raw_upload_url,
        data=json.dumps(updated_payload, ensure_ascii=False).encode("utf-8"),
        headers=_build_cpa_headers(api_token, content_type="application/json"),
        timeout=30,
        impersonate="chrome110",
    )
    if resp.status_code in (200, 201):
        return True, f"status_code={resp.status_code}"
    return False, _extract_cpa_error(resp)


def probe_cliproxy_auth_file(item: dict, api_url: str, api_token: str) -> dict:
    settings = get_settings()
    panel_failure_reason = _extract_cliproxy_item_failure_reason(item, 0)
    panel_status_code = _extract_cliproxy_status_code(item)

    result = {
        "status_code": panel_status_code,
        "failure_reason": panel_failure_reason,
        "quota": {
            "weekly_remaining_percent": None,
            "five_hour_remaining_percent": None,
            "has_five_hour_limit": False,
        },
        "ok": False,
        "source": "panel",
    }

    payload, payload_error = _build_cliproxy_probe_payload(item, settings)
    if payload is None:
        result["failure_reason"] = payload_error or result["failure_reason"] or "missing payload"
        return result

    url = _build_cliproxy_api_call_url(api_url)
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    resp = cffi_requests.post(url, headers=headers, json=payload, timeout=30, impersonate="chrome110")
    if resp.status_code != 200:
        result["source"] = "probe"
        result["failure_reason"] = _extract_cpa_error(resp)
        result["status_code"] = resp.status_code
        return result

    data = resp.json()
    status_code = data.get("status_code")
    if not isinstance(status_code, int):
        status_code = None
    result["status_code"] = status_code
    result["source"] = "probe"
    result["quota"] = _extract_quota_metrics(data)

    failure_reason = _extract_cliproxy_failure_reason(data, 0)
    if failure_reason:
        result["failure_reason"] = failure_reason
    elif status_code is not None and status_code >= 400:
        result["failure_reason"] = f"status_code={status_code}"
    else:
        result["failure_reason"] = None

    result["ok"] = bool((status_code is None or status_code < 400) and not result["failure_reason"])
    return result


def test_cliproxy_auth_file(item: dict, api_url: str, api_token: str) -> tuple[bool, str]:
    result = probe_cliproxy_auth_file(item, api_url, api_token)
    status_code = result.get("status_code")
    failure_reason = result.get("failure_reason")
    if result.get("ok"):
        if isinstance(status_code, int):
            return True, f"status_code={status_code}"
        return True, "status_code=200"
    if isinstance(status_code, int):
        suffix = f" - {failure_reason}" if failure_reason else ""
        return False, f"status_code={status_code}{suffix}"
    return False, str(failure_reason or "unknown_error")


def delete_cliproxy_auth_file(name: str, api_url: str, api_token: str) -> None:
    if not name:
        return
    url = _normalize_cpa_auth_files_url(api_url)
    resp = cffi_requests.delete(url, headers=_build_cpa_headers(api_token), params={"name": name}, timeout=30, impersonate="chrome110")
    resp.raise_for_status()


async def trigger_auto_registration(count: int, cpa_service_id: int):
    logger.info(f"触发自动注册凭证，数量: {count}, 目标CPA 服务 ID: {cpa_service_id}")
    task_uuids = [str(uuid.uuid4()) for _ in range(count)]
    batch_id = str(uuid.uuid4())
    _track_auto_register_batch(batch_id)

    settings = get_settings()
    
    email_service_type = "temp_mail"
    email_service_id = None
    email_service_pool: List[tuple[str, Optional[int]]] = []
    
    # 优先使用配置中保存的邮箱服务
    saved_email_svc = settings.cpa_auto_register_email_service
    if saved_email_svc:
        email_service_pool = _parse_auto_register_email_pool(saved_email_svc)
    if email_service_pool:
        email_service_type, email_service_id = email_service_pool[0]
    else:
        if saved_email_svc and ':' in saved_email_svc:
            parts = saved_email_svc.split(':', 1)
            email_service_type = parts[0]
            if len(parts) > 1 and parts[1] != 'default':
                try:
                    email_service_id = int(parts[1])
                except:
                    pass
        else:
            with get_db() as db:
                enabled_services = crud.get_email_services(db, enabled=True)
                if enabled_services:
                    best_svc = enabled_services[0]
                    email_service_type = best_svc.service_type
                    email_service_id = best_svc.id

    with get_db() as db:
        initial_service_id = email_service_id if len(email_service_pool) <= 1 else None
        for task_uuid in task_uuids:
            crud.create_registration_task(
                db,
                task_uuid=task_uuid,
                email_service_id=initial_service_id,
                proxy=None
            )

    auto_token_mode = "browser_http_only"
    raw_token_mode = (settings.cpa_auto_register_token_mode or "").strip().lower()
    if raw_token_mode in {"browser", "browser_http_first", "browser_http_only"}:
        auto_token_mode = raw_token_mode
    elif raw_token_mode == "http_independent":
        auto_token_mode = "browser_http_only"
    elif raw_token_mode:
        append_system_log("warning", f"自动注册 Token 获取方式 {raw_token_mode} 不受支持，回退 browser_http_only")

    asyncio.create_task(
        run_batch_registration(
            batch_id=batch_id,
            task_uuids=task_uuids,
            email_service_type=email_service_type,
            proxy=None,
            email_service_config=None,
            email_service_id=email_service_id,
            interval_min=settings.registration_sleep_min,
            interval_max=settings.registration_sleep_max,
            concurrency=settings.global_concurrency,
            mode="pipeline",
            token_mode=auto_token_mode,
            email_service_pool=email_service_pool if len(email_service_pool) > 1 else None,
            auto_upload_cpa=True,
            cpa_service_ids=[cpa_service_id],
        )
    )


_is_checking = False
_is_checking_401 = False
_is_processing_oauth_pending = False
_pending_check_once = False
_pending_check_lock = threading.Lock()
_check_abort_requested = False
_check_abort_lock = threading.Lock()
_last_config_trigger_ts = 0.0
_auto_register_batch_ids = set()
_auto_register_batch_lock = threading.Lock()


def _track_auto_register_batch(batch_id: str) -> None:
    if not batch_id:
        return
    with _auto_register_batch_lock:
        _auto_register_batch_ids.add(batch_id)


def cancel_auto_register_batches() -> int:
    """取消所有自动注册批量任务（不影响手动发起的批量注册）"""
    try:
        from ..web.task_manager import task_manager
    except Exception:
        return 0

    with _auto_register_batch_lock:
        batch_ids = list(_auto_register_batch_ids)
        _auto_register_batch_ids.clear()

    cancelled = 0
    for batch_id in batch_ids:
        try:
            task_manager.cancel_batch(batch_id)
            append_system_log("warning", f"已请求停止自动注册批量任务: {batch_id[:8]}")
            cancelled += 1
        except Exception:
            continue
    return cancelled

def _mark_pending_check_once() -> bool:
    """标记在当前检查任务结束后再补跑一次检查。"""
    global _pending_check_once
    with _pending_check_lock:
        if _pending_check_once:
            return False
        _pending_check_once = True
        return True


def _consume_pending_check_once() -> bool:
    """消费一次待执行的检查请求。"""
    global _pending_check_once
    with _pending_check_lock:
        if not _pending_check_once:
            return False
        _pending_check_once = False
        return True


def _request_abort_check() -> None:
    global _check_abort_requested
    with _check_abort_lock:
        _check_abort_requested = True


def _consume_abort_check() -> bool:
    global _check_abort_requested
    with _check_abort_lock:
        if not _check_abort_requested:
            return False
        _check_abort_requested = False
        return True


def _should_abort_check() -> bool:
    with _check_abort_lock:
        return _check_abort_requested


def request_cpa_check_once(main_loop, reason: str = "config") -> None:
    """请求立即执行一次 CPA 检查（若正在运行则排队一次）。"""
    global _last_config_trigger_ts
    now = time.time()
    # 防止短时间重复触发导致多次补跑
    if now - _last_config_trigger_ts < 3:
        append_system_log("warning", "检测任务保存过于频繁，已合并触发请求")
        return
    _last_config_trigger_ts = now
    check_cpa_services_job(main_loop, None, allow_queue=True, reason=reason)

def check_cpa_services_401_job(main_loop, manual_logs: list = None, force: bool = False):
    """快速检查并剔除面板明确报错的凭证（401/403/usage_limit_reached，不做测活）"""
    global _is_checking_401
    settings = get_settings()

    if not settings.cpa_auto_check_enabled and manual_logs is None:
        return
    if not settings.cpa_auto_check_remove_401:
        msg = "未启用 401/403/usage_limit_reached 快速剔除，任务跳过。"
        if manual_logs is not None:
            manual_logs.append(f"[WARNING] {msg}")
            append_system_log("warning", msg)
        return
    if _is_checking and not force:
        msg = "当前正在执行完整体检任务，401/403/usage_limit_reached 快速剔除本轮跳过。"
        if manual_logs is not None:
            manual_logs.append(f"[WARNING] {msg}")
            append_system_log("warning", msg)
        return
    if _is_checking_401:
        msg = "当前已有 401/403/usage_limit_reached 快速剔除任务在运行，本轮跳过。"
        if manual_logs is not None:
            manual_logs.append(f"[WARNING] {msg}")
            append_system_log("warning", msg)
        return

    force_full_check_running = _is_checking and force
    _is_checking_401 = True

    def _log(msg: str, level: str = 'info'):
        log_func = getattr(logger, level, logger.info)
        log_func(msg)
        append_system_log(level, msg)
        if manual_logs is not None:
            manual_logs.append(f"[{level.upper()}] {msg}")

    if force_full_check_running:
        _log("当前正在执行完整体检任务，已按手动请求强制执行 401/403/usage_limit_reached 快速剔除。", "warning")
    _log("开始快速检查 CPA 401/403/usage_limit_reached 标记凭证...")
    try:
        with get_db() as db:
            services = crud.get_cpa_services(db, enabled=True)
            if not services:
                _log("警告：当前没有任何启用的 CPA 服务！请先配置并启用 CPA 服务。", "warning")
            for svc in services:
                try:
                    _log(f"检查 CPA 服务(401/403/usage_limit_reached 快速剔除): {svc.name}")
                    files, total_count, skipped_count = fetch_cliproxy_auth_files(svc.api_url, svc.api_token)
                    if not files:
                        if total_count > 0:
                            _log(
                                f"CPA 服务 {svc.name} 获取到 {total_count} 个凭证，"
                                f"筛选后没有 Codex 凭证（已跳过 {skipped_count} 个非 Codex/未标注凭证）",
                                'warning',
                            )
                        else:
                            _log(f"CPA 服务 {svc.name} 没有凭证", 'warning')
                        continue

                    removed_401 = 0
                    for item in files:
                        remove_reason = _extract_cliproxy_panel_direct_reason(item)
                        if not remove_reason:
                            continue
                        name = str(item.get("name", "")).strip()
                        if not name:
                            _log("检测到面板标记 401/403/usage_limit_reached 的凭证但缺少名称，已跳过快速剔除", 'warning')
                            continue
                        if not _is_cpa_codex_auth_file(item):
                            _log(f"面板标记 401/403/usage_limit_reached 的凭证 {name} 非 Codex，按策略仅跳过不清理", 'warning')
                            continue
                        try:
                            delete_cliproxy_auth_file(name, svc.api_url, svc.api_token)
                            removed_401 += 1
                            _log(f"面板快速剔除: {name} ({remove_reason})", 'warning')
                        except Exception as e:
                            _log(f"面板快速剔除 {name} 失败: {e}", 'error')

                    _log(f"CPA 服务 {svc.name} 401/403/usage_limit_reached 快速剔除完成，剔除: {removed_401}")
                except Exception as e:
                    _log(f"检查 CPA 服务 {svc.id} ({svc.name}) 401/403/usage_limit_reached 快速剔除异常: {e}", 'error')
    except Exception as e:
        _log(f"401/403/usage_limit_reached 快速剔除任务异常: {e}", 'error')
    finally:
        _is_checking_401 = False


def _trigger_auto_registration_if_needed(main_loop, svc, available_count: int, settings, _log) -> None:
    if not settings.cpa_auto_register_enabled:
        return
    threshold = int(settings.cpa_auto_register_threshold or 0)
    if threshold <= 0:
        return
    if available_count >= threshold:
        return

    to_register = int(settings.cpa_auto_register_batch_count or 0)
    _log(
        f"CPA 服务 {svc.name} 当前可用凭证 {available_count} 低于阈值 {threshold}，"
        f"触发自动注册 {to_register} 个",
        "warning",
    )
    if to_register <= 0:
        _log("自动注册批量数量 <= 0，已跳过触发", "warning")
        return
    try:
        if main_loop:
            asyncio.run_coroutine_threadsafe(
                trigger_auto_registration(to_register, svc.id),
                main_loop,
            )
        else:
            _log("调度错误: 没有提供有效的 main_loop 导致无法开启协程", "error")
    except Exception as e:
        _log(f"调度自动注册任务失败: {e}", "error")


def _apply_policy_action(rule: dict, item: dict, svc, _log) -> tuple[bool, bool, bool]:
    """
    执行动作。
    返回: (执行成功, 是否已删除文件, 是否产生状态变化)
    """
    name = str(item.get("name", "")).strip()
    if not name:
        _log("命中规则但凭证缺少 name，已跳过动作执行", "warning")
        return False, False, False

    action = rule.get("action", "remove")
    rule_name = rule.get("name") or rule.get("id") or "unnamed_rule"

    if action == "remove":
        try:
            delete_cliproxy_auth_file(name, svc.api_url, svc.api_token)
            _log(f"策略动作[剔除] 成功: {name} (规则: {rule_name})", "warning")
            return True, True, True
        except Exception as e:
            _log(f"策略动作[剔除] 失败: {name} ({e})", "error")
            return False, False, False

    target_enabled = action == "enable"
    current_status = _extract_item_status_for_rule(item)
    desired_status = "enabled" if target_enabled else "disabled"
    if current_status == desired_status:
        _log(f"策略动作[{action}] 跳过: {name} 已是 {desired_status}", "info")
        return True, False, False

    ok, msg = set_cliproxy_auth_file_enabled(
        item=item,
        name=name,
        enabled=target_enabled,
        api_url=svc.api_url,
        api_token=svc.api_token,
    )
    if not ok:
        _log(f"策略动作[{action}] 失败: {name} ({msg})", "error")
        return False, False, False

    item["status"] = desired_status
    item["enabled"] = target_enabled
    _log(f"策略动作[{action}] 成功: {name} ({msg})", "warning")
    return True, False, True


def _match_invalid_rule(rule: dict, item: dict, plan_type: str, item_status: str, invalid_reason: Optional[str]) -> bool:
    if not invalid_reason:
        return False
    if rule.get("task") != "invalid":
        return False
    if rule.get("condition") != "invalid_signal":
        return False
    if not _is_rule_plan_match(rule, plan_type):
        return False
    if not _is_rule_status_match(rule, item_status):
        return False
    return True


def _resolve_rule_metric(rule: dict, quota: dict) -> tuple[Optional[float], str]:
    condition = rule.get("condition")
    if condition == "weekly_remaining_percent":
        return quota.get("weekly_remaining_percent"), "周限额剩余"
    if condition == "five_hour_remaining_percent":
        value = quota.get("five_hour_remaining_percent")
        if value is None and rule.get("fallback_to_weekly"):
            return quota.get("weekly_remaining_percent"), "5小时限额缺失，回退周限额剩余"
        return value, "5小时限额剩余"
    return None, "未知指标"


def _match_quota_rule(rule: dict, item: dict, plan_type: str, item_status: str, quota: dict) -> tuple[bool, Optional[float], str]:
    if rule.get("task") != "quota":
        return False, None, ""
    if rule.get("condition") not in {"weekly_remaining_percent", "five_hour_remaining_percent"}:
        return False, None, ""
    if not _is_rule_plan_match(rule, plan_type):
        return False, None, ""
    if not _is_rule_status_match(rule, item_status):
        return False, None, ""

    metric_value, metric_label = _resolve_rule_metric(rule, quota)
    if metric_value is None:
        return False, None, metric_label

    operator = rule.get("operator", "lt")
    threshold = float(rule.get("threshold", 0) or 0)
    matched = _compare_threshold(float(metric_value), operator, threshold)
    return matched, float(metric_value), metric_label


def _apply_invalid_rules_for_service(
    svc,
    files: List[dict],
    invalid_rules: List[dict],
    check_mode: str,
    settings,
    _log,
) -> tuple[List[dict], dict]:
    stats = {
        "input_total": len(files or []),
        "processed": 0,
        "with_signal": 0,
        "rule_matched": 0,
        "rule_unmatched": 0,
        "action_success": 0,
        "action_failed": 0,
        "removed": 0,
        "status_changed": 0,
        "status_noop": 0,
    }
    if not files:
        return files, stats
    if not invalid_rules:
        _log("未配置失效策略规则，任务A已跳过。")
        return files, stats

    remaining_files: List[dict] = []
    for item in files:
        if _should_abort_check():
            _consume_abort_check()
            _log("检测任务收到中止请求，终止失效策略任务并准备重启。", "warning")
            break
        stats["processed"] += 1

        name = str(item.get("name", "")).strip() or "<unknown>"
        plan_type = _extract_item_plan_type(item)
        item_status = _extract_item_status_for_rule(item)

        status_code = None
        invalid_reason = None
        if check_mode == "probe":
            if settings.cpa_auto_check_sleep_seconds > 0:
                time.sleep(settings.cpa_auto_check_sleep_seconds)
            probe_result = probe_cliproxy_auth_file(item, svc.api_url, svc.api_token)
            status_code = probe_result.get("status_code")
            invalid_reason = probe_result.get("failure_reason")
        else:
            status_code = _extract_cliproxy_status_code(item)
            invalid_reason = _extract_cliproxy_item_failure_reason(item, 0)

        if not invalid_reason and isinstance(status_code, int) and status_code >= 400:
            invalid_reason = f"status_code={status_code}"

        if not invalid_reason:
            remaining_files.append(item)
            continue

        stats["with_signal"] += 1
        matched_rule = None
        for rule in invalid_rules:
            if _match_invalid_rule(rule, item, plan_type, item_status, invalid_reason):
                matched_rule = rule
                break

        if not matched_rule:
            stats["rule_unmatched"] += 1
            _log(
                f"失效信号未命中策略，保留凭证: {name} (套餐: {plan_type}, 状态: {item_status}, 原因: {invalid_reason})",
                "warning",
            )
            remaining_files.append(item)
            continue

        stats["rule_matched"] += 1
        rule_name = matched_rule.get("name") or matched_rule.get("id") or "unnamed_rule"
        _log(
            f"命中失效策略: {name} (规则: {rule_name}, 套餐: {plan_type}, 状态: {item_status}, 原因: {invalid_reason})",
            "warning",
        )
        _ok, removed, changed = _apply_policy_action(matched_rule, item, svc, _log)
        if _ok:
            stats["action_success"] += 1
        else:
            stats["action_failed"] += 1
        if removed:
            stats["removed"] += 1
        if changed:
            stats["status_changed"] += 1
        elif _ok and matched_rule.get("action") in {"enable", "disable"}:
            stats["status_noop"] += 1
        if not removed:
            remaining_files.append(item)

    return remaining_files, stats


def _apply_quota_rules_for_service(
    svc,
    files: List[dict],
    quota_rules: List[dict],
    settings,
    _log,
) -> tuple[List[dict], dict]:
    stats = {
        "input_total": len(files or []),
        "processed": 0,
        "candidate_filtered_out": 0,
        "rule_matched": 0,
        "rule_unmatched": 0,
        "action_success": 0,
        "action_failed": 0,
        "removed": 0,
        "status_changed": 0,
        "status_noop": 0,
        "usage_limit_forced_zero": 0,
    }
    if not files:
        return files, stats
    if not quota_rules:
        _log("未配置限额策略规则，任务B已跳过。")
        return files, stats

    remaining_files: List[dict] = []
    for item in files:
        if _should_abort_check():
            _consume_abort_check()
            _log("检测任务收到中止请求，终止限额策略任务并准备重启。", "warning")
            break
        stats["processed"] += 1

        name = str(item.get("name", "")).strip() or "<unknown>"
        plan_type = _extract_item_plan_type(item)
        item_status = _extract_item_status_for_rule(item)

        candidate_rules = [
            rule
            for rule in quota_rules
            if _is_rule_plan_match(rule, plan_type) and _is_rule_status_match(rule, item_status)
        ]
        if not candidate_rules:
            stats["candidate_filtered_out"] += 1
            remaining_files.append(item)
            continue

        if settings.cpa_auto_check_sleep_seconds > 0:
            time.sleep(settings.cpa_auto_check_sleep_seconds)
        probe_result = probe_cliproxy_auth_file(item, svc.api_url, svc.api_token)
        quota = probe_result.get("quota") or {}
        if _is_usage_limit_reached_text(probe_result.get("failure_reason")):
            stats["usage_limit_forced_zero"] += 1
            _log(f"检测到 usage_limit_reached，按额度耗尽(0%)处理: {name}", "warning")

        matched_rule = None
        matched_metric_value = None
        matched_metric_label = ""
        for rule in candidate_rules:
            matched, metric_value, metric_label = _match_quota_rule(rule, item, plan_type, item_status, quota)
            if matched:
                matched_rule = rule
                matched_metric_value = metric_value
                matched_metric_label = metric_label
                break

        if not matched_rule:
            stats["rule_unmatched"] += 1
            remaining_files.append(item)
            continue

        stats["rule_matched"] += 1
        rule_name = matched_rule.get("name") or matched_rule.get("id") or "unnamed_rule"
        metric_text = _format_percent(matched_metric_value) if matched_metric_value is not None else "N/A"
        _log(
            f"命中限额策略: {name} (规则: {rule_name}, 套餐: {plan_type}, 状态: {item_status}, {matched_metric_label}: {metric_text}%)",
            "warning",
        )
        _ok, removed, changed = _apply_policy_action(matched_rule, item, svc, _log)
        if _ok:
            stats["action_success"] += 1
        else:
            stats["action_failed"] += 1
        if removed:
            stats["removed"] += 1
        if changed:
            stats["status_changed"] += 1
        elif _ok and matched_rule.get("action") in {"enable", "disable"}:
            stats["status_noop"] += 1
        if not removed:
            remaining_files.append(item)

    return remaining_files, stats


def check_cpa_services_job(
    main_loop,
    manual_logs: list = None,
    allow_queue: bool = False,
    reason: str = "scheduler",
):
    """定时检查所有启用的 CPA 服务（失效任务与限额任务分离）"""
    global _is_checking
    settings = get_settings()
    check_enabled = bool(getattr(settings, "cpa_auto_check_enabled", False))
    register_enabled = bool(getattr(settings, "cpa_auto_register_enabled", False))
    # 手动触发允许始终执行；定时循环仅在“凭证体检”或“自动补注册”至少启用一项时运行。
    if manual_logs is None and not (check_enabled or register_enabled):
        return

    if _is_checking:
        if allow_queue and manual_logs is None:
            _request_abort_check()
            queued = _mark_pending_check_once()
            msg = "检测任务运行中，已请求中止并重启以应用新配置。" if queued else "检测任务运行中，已存在重启请求，已合并。"
            append_system_log("warning", msg)
        else:
            msg = "当前已有一个检查任务在运行，本次并发请求将被跳过。"
            if manual_logs is not None:
                manual_logs.append(f"[WARNING] {msg}")
                # only inject system log if triggered manually to not pollute too much
                append_system_log("warning", msg)
        return
        
    _is_checking = True

    def _log(msg: str, level: str = 'info'):
        log_func = getattr(logger, level, logger.info)
        log_func(msg)
        append_system_log(level, msg)
        if manual_logs is not None:
            manual_logs.append(f"[{level.upper()}] {msg}")

    _log("开始检查 CPA (CLIProxy) 服务...")
    try:
        policy_rules: List[dict] = []
        invalid_rules: List[dict] = []
        quota_rules: List[dict] = []
        if check_enabled:
            policy_rules = _load_cpa_policy_rules(settings)
            invalid_rules = [rule for rule in policy_rules if rule.get("enabled") and rule.get("task") == "invalid"]
            quota_rules = [rule for rule in policy_rules if rule.get("enabled") and rule.get("task") == "quota"]
            _log(
                f"已加载策略规则 {len(policy_rules)} 条（失效: {len(invalid_rules)}，限额: {len(quota_rules)}）"
            )
        else:
            _log("凭证体检未启用，仅执行凭证数量监控与自动补货。")

        with get_db() as db:
            services = crud.get_cpa_services(db, enabled=True)
            if not services:
                _log("警告：当前没有任何启用的 CPA 服务！请先配置并启用 CPA 服务。", "warning")
            for svc in services:
                if _should_abort_check():
                    _consume_abort_check()
                    _log("检测任务收到中止请求，准备重启以应用新配置。", "warning")
                    break

                files: List[dict] = []
                try:
                    _log(f"检查 CPA 服务: {svc.name}")
                    files, total_count, skipped_count = fetch_cliproxy_auth_files(svc.api_url, svc.api_token)
                    if not files:
                        if total_count > 0:
                            _log(
                                f"CPA 服务 {svc.name} 获取到 {total_count} 个凭证，"
                                f"筛选后没有 Codex 凭证（已跳过 {skipped_count} 个非 Codex/未标注凭证）",
                                'warning',
                            )
                        else:
                            _log(f"CPA 服务 {svc.name} 没有凭证", 'warning')
                    else:
                        _log(
                            f"CPA 服务 {svc.name} 获取到 {total_count} 个凭证，"
                            f"筛选后保留 {len(files)} 个 Codex 凭证，跳过 {skipped_count} 个"
                        )
                        if check_enabled:
                            check_mode = (getattr(settings, "cpa_auto_check_mode", "panel") or "panel").lower()
                            if check_mode not in ("probe", "panel"):
                                check_mode = "panel"

                            _log(
                                "任务A/失效检测开始（任务A=失效规则组，不是规则编号）: "
                                f"模式={check_mode}, 生效规则={len(invalid_rules)}条, 处理范围=Codex {len(files)}个"
                            )
                            files_after_invalid, invalid_stats = _apply_invalid_rules_for_service(
                                svc=svc,
                                files=files,
                                invalid_rules=invalid_rules,
                                check_mode=check_mode,
                                settings=settings,
                                _log=_log,
                            )
                            _log(
                                "任务A/失效检测完成（仅统计 Codex 处理中的数量，非服务全量）: "
                                f"处理前={len(files)}, 处理后={len(files_after_invalid)}, "
                                f"有信号={invalid_stats.get('with_signal', 0)}, "
                                f"命中规则={invalid_stats.get('rule_matched', 0)}, "
                                f"未命中规则={invalid_stats.get('rule_unmatched', 0)}, "
                                f"动作成功={invalid_stats.get('action_success', 0)}, "
                                f"动作失败={invalid_stats.get('action_failed', 0)}, "
                                f"剔除={invalid_stats.get('removed', 0)}, "
                                f"状态变更(启用/禁用)={invalid_stats.get('status_changed', 0)}, "
                                f"状态已满足跳过={invalid_stats.get('status_noop', 0)}"
                            )

                            _log(
                                "任务B/限额策略开始（任务B=限额规则组，不是规则编号）: "
                                f"生效规则={len(quota_rules)}条, 承接数量={len(files_after_invalid)}"
                            )
                            files_after_quota, quota_stats = _apply_quota_rules_for_service(
                                svc=svc,
                                files=files_after_invalid,
                                quota_rules=quota_rules,
                                settings=settings,
                                _log=_log,
                            )
                            _log(
                                "任务B/限额策略完成（仅统计 Codex 处理中的数量，非服务全量）: "
                                f"处理前={len(files_after_invalid)}, 处理后={len(files_after_quota)}, "
                                f"候选规则过滤后跳过={quota_stats.get('candidate_filtered_out', 0)}, "
                                f"命中规则={quota_stats.get('rule_matched', 0)}, "
                                f"未命中规则={quota_stats.get('rule_unmatched', 0)}, "
                                f"动作成功={quota_stats.get('action_success', 0)}, "
                                f"动作失败={quota_stats.get('action_failed', 0)}, "
                                f"剔除={quota_stats.get('removed', 0)}, "
                                f"状态变更(启用/禁用)={quota_stats.get('status_changed', 0)}, "
                                f"状态已满足跳过={quota_stats.get('status_noop', 0)}, "
                                f"usage_limit_reached按0%处理={quota_stats.get('usage_limit_forced_zero', 0)}"
                            )
                        else:
                            _log("体检开关关闭，跳过失效/限额策略，仅保留数量监控。")

                    refreshed_files, refreshed_total_count, refreshed_skipped_count = fetch_cliproxy_auth_files(
                        svc.api_url, svc.api_token
                    )
                    enabled_count = sum(1 for item in refreshed_files if _extract_item_status_for_rule(item) == "enabled")
                    _log(
                        f"CPA 服务 {svc.name} 策略执行后可用凭证(Codex): {enabled_count} / {len(refreshed_files)} "
                        f"（服务总凭证: {refreshed_total_count}, 非Codex跳过: {refreshed_skipped_count}）"
                    )
                    _trigger_auto_registration_if_needed(main_loop, svc, enabled_count, settings, _log)
                except Exception as e:
                    _log(f"检查 CPA 服务 {svc.id} ({svc.name}) 异常/鉴权失败: {e}", 'error')
                    _log("本服务本轮检查失败，自动注册判断已跳过。", "warning")

    except Exception as e:
        _log(f"定时检查 CPA 任务异常: {e}", 'error')
    finally:
        _is_checking = False

    if manual_logs is None and _consume_pending_check_once():
        latest_settings = get_settings()
        if latest_settings.cpa_auto_check_enabled or latest_settings.cpa_auto_register_enabled:
            _log("检测任务因配置更新请求将立即再次执行", "warning")
            check_cpa_services_job(main_loop, None, allow_queue=False, reason="pending")


def process_oauth_pending_job(manual_logs: list = None):
    """处理待 OAuth 授权队列。"""
    global _is_processing_oauth_pending
    if _is_processing_oauth_pending:
        msg = "待授权队列任务正在执行，本轮跳过。"
        if manual_logs is not None:
            manual_logs.append(f"[WARNING] {msg}")
        append_system_log("warning", msg)
        return {"picked": 0, "success": 0, "failed": 0, "rate_limited": 0, "requeued": 0, "uploaded": 0}

    _is_processing_oauth_pending = True
    try:
        summary = process_pending_oauth_once(logs=manual_logs)
        overview = get_oauth_pending_overview()
        append_system_log(
            "info",
            "待授权队列处理完成："
            f"picked={summary.get('picked', 0)}, "
            f"success={summary.get('success', 0)}, "
            f"recovered_running={summary.get('recovered_running', 0)}, "
            f"requeued={summary.get('requeued', 0)}, "
            f"rate_limited={summary.get('rate_limited', 0)}, "
            f"failed={summary.get('failed', 0)}, "
            f"queue_pending={overview.get('pending', 0)}, "
            f"queue_running={overview.get('running', 0)}, "
            f"queue_rate_limited={overview.get('rate_limited', 0)}, "
            f"queue_failed={overview.get('failed', 0)}",
        )
        return summary
    except Exception as e:
        append_system_log("error", f"待授权队列处理异常: {e}")
        if manual_logs is not None:
            manual_logs.append(f"[ERROR] 待授权队列处理异常: {e}")
        return {"picked": 0, "success": 0, "failed": 0, "rate_limited": 0, "requeued": 0, "uploaded": 0}
    finally:
        _is_processing_oauth_pending = False


async def _scheduler_loop():
    """调度器主循环"""
    await asyncio.sleep(5) # 启动后延迟 5 秒开始
    loop = asyncio.get_running_loop()
    while True:
        settings = get_settings()
        try:
            await loop.run_in_executor(None, check_cpa_services_job, loop, None)
        except Exception as e:
            logger.error(f"Scheduler loop exception: {e}")
        
        # 休眠指定间隔
        interval_min = settings.cpa_auto_check_interval
        if interval_min < 1:
            interval_min = 1
        await asyncio.sleep(interval_min * 60)


async def _scheduler_401_loop():
    """401 快速剔除调度器主循环"""
    await asyncio.sleep(8) # 启动后延迟 8 秒开始
    loop = asyncio.get_running_loop()
    while True:
        settings = get_settings()
        try:
            await loop.run_in_executor(None, check_cpa_services_401_job, loop, None)
        except Exception as e:
            logger.error(f"Scheduler 401 loop exception: {e}")
        interval_min = getattr(settings, "cpa_auto_check_remove_401_interval", 3) or 3
        if interval_min < 1:
            interval_min = 1
        await asyncio.sleep(interval_min * 60)


async def _scheduler_oauth_pending_loop():
    """待授权 OAuth 定时补授权循环。"""
    await asyncio.sleep(12)
    loop = asyncio.get_running_loop()
    while True:
        settings = get_settings()
        try:
            if settings.oauth_pending_enabled:
                await loop.run_in_executor(None, process_oauth_pending_job, None)
        except Exception as e:
            logger.error(f"Scheduler oauth pending loop exception: {e}")
        interval_seconds = int(getattr(settings, "oauth_pending_poll_interval_seconds", 60) or 60)
        if interval_seconds < 10:
            interval_seconds = 10
        await asyncio.sleep(interval_seconds)


def start_scheduler():
    """启动调度器"""
    logger.info("启动后台调度器，负责定时任务...")
    loop = asyncio.get_event_loop()
    loop.create_task(_scheduler_loop())
    loop.create_task(_scheduler_401_loop())
    loop.create_task(_scheduler_oauth_pending_loop())
