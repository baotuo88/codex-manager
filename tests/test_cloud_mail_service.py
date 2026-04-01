from src.services.cloud_mail import CloudMailService
from datetime import datetime, timezone


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


class FakeHTTPClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append({
            "url": url,
            "kwargs": kwargs,
        })
        if not self.responses:
            raise AssertionError(f"未准备响应: POST {url}")
        return self.responses.pop(0)


def _build_service(responses):
    service = CloudMailService({
        "base_url": "https://cloudmail.example.test",
        "api_token": "token-1",
        "default_domain": "7thcity.com",
        "poll_interval": 1,
    })
    service.http_client = FakeHTTPClient(responses)
    return service


def test_get_verification_code_prefers_recent_message_after_otp_sent_at():
    service = _build_service([
        FakeResponse(
            payload={
                "code": 200,
                "message": "success",
                "data": [
                    {
                        "emailId": 6111,
                        "createTime": 1_000_000,
                        "subject": "Your ChatGPT code is 810012",
                        "content": "<html>Your ChatGPT code is 810012</html>",
                    },
                    {
                        "emailId": 6112,
                        "createTime": 1_000_030,
                        "subject": "Your ChatGPT code is 636810",
                        "content": "<html>Your ChatGPT code is 636810</html>",
                    },
                ],
            }
        )
    ])

    email = "tester@7thcity.com"
    code = service.get_verification_code(
        email=email,
        timeout=2,
        otp_sent_at=1_000_020,
    )

    assert code == "636810"
    assert service._last_message_id_cache[email] == "6112"
    assert service._last_code_cache[email] == "636810"


def test_get_verification_code_skips_cached_message_id_and_uses_next_candidate():
    service = _build_service([
        FakeResponse(
            payload={
                "code": 200,
                "message": "success",
                "data": [
                    {
                        "emailId": 7001,
                        "createTime": 1_000_050,
                        "subject": "Your ChatGPT code is 111111",
                    },
                    {
                        "emailId": 7002,
                        "createTime": 1_000_040,
                        "subject": "Your ChatGPT code is 222222",
                    },
                ],
            }
        )
    ])
    email = "tester@7thcity.com"
    service._last_message_id_cache[email] = "7001"

    code = service.get_verification_code(
        email=email,
        timeout=2,
        otp_sent_at=1_000_035,
    )

    assert code == "222222"
    assert service._last_message_id_cache[email] == "7002"
    assert service._last_code_cache[email] == "222222"


def test_get_verification_code_accepts_naive_utc_create_time_after_otp_sent_at():
    otp_sent_at = datetime(2026, 4, 1, 18, 43, 48, tzinfo=timezone.utc).timestamp()
    service = _build_service([
        FakeResponse(
            payload={
                "code": 200,
                "message": "success",
                "data": [
                    {
                        "emailId": 6115,
                        "createTime": "2026-04-01 18:43:48",
                        "subject": "Your ChatGPT code is 095984",
                    }
                ],
            }
        )
    ])
    email = "tester@7thcity.com"

    code = service.get_verification_code(
        email=email,
        timeout=2,
        otp_sent_at=otp_sent_at,
    )

    assert code == "095984"
    assert service._last_message_id_cache[email] == "6115"
