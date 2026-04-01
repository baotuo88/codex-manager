import time
import logging
import random
import uuid
import re
from datetime import datetime
from typing import Optional, Dict

from ..services.base import BaseEmailService
from ..config.constants import generate_random_user_info, DEFAULT_PASSWORD_LENGTH, PASSWORD_CHARSET, OTP_CODE_PATTERN
from .register import RegistrationResult

logger = logging.getLogger(__name__)

class BrowserRegistrationEngine:
    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger = None,
        task_uuid: Optional[str] = None,
    ):
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid
        
        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.email_info: Optional[Dict] = None
        self.logs: list = []
        self._otp_sent_at: Optional[float] = None

    def _log(self, message: str, level: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] [Browser] {message}"
        self.logs.append(log_message)
        if self.callback_logger:
            self.callback_logger(log_message)
        if level == "error": logger.error(message)
        elif level == "warning": logger.warning(message)
        else: logger.info(message)

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        return ''.join(random.choices(PASSWORD_CHARSET, k=length))

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
            
    def _random_delay(self, low=0.5, high=2.0):
        time.sleep(random.uniform(low, high))

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
        except ImportError:
            self._log("未找到 playwright，请运行: uv pip install playwright && uv run playwright install chromium", "error")
            result.error_message = "Playwright not installed"
            return result

        if not self._create_email():
            result.error_message = "创建邮箱失败"
            return result
            
        result.email = self.email
        self.password = self._generate_password()
        result.password = self.password
        
        user_info = generate_random_user_info()
        name = user_info['name']
        birthdate = user_info['birthdate']

        self._log(f"使用有头浏览器注册，分配邮箱: {self.email}")
        
        with sync_playwright() as p:
            launch_args = {
                "headless": False,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--incognito",
                ]
            }
            if self.proxy_url:
                launch_args["proxy"] = {"server": self.proxy_url}
                
            browser = p.chromium.launch(**launch_args)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},
                device_scale_factor=1,
            )
            context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            page = context.new_page()
            
            try:
                self._log("访问 ChatGPT 首页获取验证环境...")
                # 先访问首页，获取正常的 session 状态
                page.goto("https://chatgpt.com/", wait_until="commit", timeout=60000)
                
                try:
                    page.wait_for_selector('[data-testid="signup-button"], [data-testid="login-button"]', timeout=30000)
                    self._random_delay(1.0, 2.0)
                    self._log("点击注册/登录按钮...")
                    if page.locator('[data-testid="signup-button"]').count() > 0:
                        page.locator('[data-testid="signup-button"]').first.click()
                    elif page.locator('[data-testid="login-button"]').count() > 0:
                        page.locator('[data-testid="login-button"]').first.click()
                except Exception as e:
                    self._log("未找到首页按钮，尝试直接使用 signup 链接...", "warning")
                    page.goto("https://chatgpt.com/api/auth/signin/openai?prompt=login&screen_hint=signup", wait_until="commit")
                
                # 等待输入邮箱的界面
                page.wait_for_selector("input[type='email']", timeout=60000)
                self._random_delay(2.0, 4.0)
                self._log("填写邮箱...")
                page.fill("input[type='email']", self.email)
                self._random_delay(1.0, 2.0)
                page.click("button[type='submit']")
                
                # 等待密码输入框
                try:
                    self._log("等待进入密码页面...")
                    page.wait_for_selector("input[type='password']", timeout=60000)
                    self._log("填写密码...")
                    self._random_delay(1.0, 2.5)
                    page.fill("input[type='password']", self.password)
                    self._random_delay(1.0, 2.0)
                    page.click("button[type='submit']")
                except PlaywrightTimeoutError:
                    self._log("没找到密码输入框，可能卡在人机验证或页面加载缓慢。", "error")
                    result.error_message = "无法进入密码页面"
                    return result
                
                self._otp_sent_at = time.time()
                self._log("等待加载并请求验证码...")
                
                # 处理可能出现的验证码/Name/Birthdate页面
                try:
                    page.wait_for_selector("input[name='code'], input[name='name'], input[name='first-name'], h2:has-text('Verify your email')", timeout=60000)
                except PlaywrightTimeoutError:
                     self._log("等待验证码/信息填写页面超时，网络可能过于拥堵。继续尝试...")

                # 提取OTP
                email_id = self.email_info.get("service_id") if self.email_info else None
                otp_code = self.email_service.get_verification_code(
                    email=self.email,
                    email_id=email_id,
                    timeout=120,
                    pattern=OTP_CODE_PATTERN,
                    otp_sent_at=self._otp_sent_at,
                )
                
                if not otp_code:
                    self._log("等待验证码超时", "error")
                    result.error_message = "收取验证码超时"
                    return result
                    
                self._log(f"收到验证码: {otp_code}，正在自动填写...")
                
                # 尝试填写所有的验证码格子，或者是完整的输入框
                if page.locator("input[data-index='0']").count() > 0:
                    for i, char in enumerate(otp_code):
                        page.fill(f"input[data-index='{i}']", char)
                elif page.locator("input[name='code']").count() > 0:
                    page.fill("input[name='code']", otp_code)
                    page.click("button[type='submit']")
                else:
                    self._log("未检测到验证码输入框，可能会自动跳转...")
                
                # 填写个人信息
                try:
                    self._log("等待加载个人信息页面...")
                    page.wait_for_selector("input[name='name'], input[name='fullname'], input[name='first-name']", timeout=60000)
                    self._log("填写姓名...")
                    self._random_delay(1.0, 2.0)
                    if page.locator("input[name='first-name']").count() > 0:
                        name_parts = name.split(" ")
                        page.fill("input[name='first-name']", name_parts[0])
                        if len(name_parts) > 1:
                            page.fill("input[name='last-name']", name_parts[1])
                    elif page.locator("input[name='fullname']").count() > 0:
                        page.fill("input[name='fullname']", name)
                    else:
                        page.fill("input[name='name']", name)
                        
                    self._random_delay(0.5, 1.5)
                    try:
                        aria_year = page.locator('div[data-type="year"]')
                        aria_month = page.locator('div[data-type="month"]')
                        aria_day = page.locator('div[data-type="day"]')
                        selects = page.locator("select")
                        
                        parts = birthdate.split("-")
                        y_str = parts[0]
                        m_str = str(int(parts[1]))
                        d_str = str(int(parts[2]))

                        if aria_year.count() > 0 and aria_month.count() > 0 and aria_day.count() > 0:
                            self._log("检测到全新分段式(React-Aria)生日输入框...")
                            aria_year.first.click()
                            page.keyboard.type(y_str)
                            self._random_delay(0.1, 0.3)
                            
                            aria_month.first.click()
                            page.keyboard.type(m_str)
                            self._random_delay(0.1, 0.3)
                            
                            aria_day.first.click()
                            page.keyboard.type(d_str)
                            self._random_delay(0.2, 0.5)
                            
                        elif selects.count() >= 3:
                            for i in range(selects.count()):
                                s_loc = selects.nth(i)
                                options_texts = s_loc.locator("option").all_inner_texts()
                                max_num = 0
                                for text in options_texts:
                                    match = re.search(r'\d+', text)
                                    if match: max_num = max(max_num, int(match.group()))
                                
                                target_val = None
                                if max_num > 31: target_val = y_str
                                elif max_num == 12: target_val = m_str
                                elif max_num == 31: target_val = d_str
                                else:
                                    if len(options_texts) in (12, 13): target_val = m_str
                                    elif len(options_texts) in (31, 32): target_val = d_str
                                
                                if target_val:
                                    val_to_select = s_loc.evaluate(f'''(sel) => {{
                                        let target = "{target_val}";
                                        let targetPad = ("0" + target).slice(-2);
                                        for (let o of sel.options) {{
                                            if (o.value === target || o.value === targetPad) return o.value;
                                            if (o.text.trim() === target || o.text.trim() === targetPad || 
                                                o.text.trim() === target + "月" || o.text.trim() === targetPad + "月") return o.value;
                                        }}
                                        return null;
                                    }}''')
                                    if val_to_select:
                                        s_loc.select_option(value=val_to_select)
                                        self._random_delay(0.2, 0.4)
                        else:
                            bday_locator = page.locator("input[name='birthdate'], input[name='birthday'], input[id*='date'], input[placeholder*='YYYY']")
                            if bday_locator.count() > 0:
                                bday_input = bday_locator.first
                                placeholder = (bday_input.get_attribute("placeholder") or "").upper()
                                parts = birthdate.split("-") # YYYY-MM-DD
                                if "DD" in placeholder and "MM" in placeholder and placeholder.index("DD") < placeholder.index("MM"):
                                    formatted = f"{parts[2]}{parts[1]}{parts[0]}" # DDMMYYYY
                                else:
                                    formatted = f"{parts[1]}{parts[2]}{parts[0]}" # MMDDYYYY
                                
                                bday_input.click()
                                bday_input.fill("")
                                page.keyboard.type(formatted, delay=50)
                                if not bday_input.input_value():
                                    bday_input.fill(f"{parts[1]}/{parts[2]}/{parts[0]}")
                    except Exception as e:
                        self._log(f"填写生日输入异常: {e}", "warning")
                    self._random_delay(0.3, 1.0)
                    
                    # 提交
                    if page.locator("button:has-text('Agree')").count() > 0:
                         page.click("button:has-text('Agree')")
                    elif page.locator("button[type='submit']").count() > 0:
                         page.click("button[type='submit']")
                    elif page.locator("button:has-text('Continue')").count() > 0:
                         page.click("button:has-text('Continue')")
                except Exception as e:
                    self._log(f"填写生日出现异常，可能界面不符: {e}", "warning")
                
                # 等待最终跳转回 ChatGPT，获取 /api/auth/session
                self._log("等待最终认证完成...")
                page.wait_for_url("**/chatgpt.com**", timeout=45000)
                
                self._log("导航到 /api/auth/session 读取 tokens...")
                page.goto("https://chatgpt.com/api/auth/session")
                try:
                    session_text = page.locator("body").inner_text()
                    import json
                    session_data = json.loads(session_text)
                    access_token = session_data.get("accessToken")
                    refresh_token = session_data.get("refreshToken", "")
                    id_token = session_data.get("idToken", "")
                    
                    # 从 cookies 里拿 session token
                    cookies = context.cookies()
                    session_cookie = ""
                    for c in cookies:
                        if c["name"] == "__Secure-next-auth.session-token":
                            session_cookie = c["value"]
                            break
                            
                    if access_token:
                        self._log("成功获取到 Access Token!")
                        result.success = True
                        result.access_token = access_token
                        result.refresh_token = refresh_token
                        result.id_token = id_token
                        result.session_token = session_cookie
                        result.account_id = "extracted_later"
                        result.source = "browser"
                        result.metadata = {
                            "email_service": self.email_service.service_type.value,
                            "proxy_used": self.proxy_url,
                            "token_mode": "browser",
                            "token_source": "playwright",
                            "registered_at": datetime.now().isoformat()
                        }
                    else:
                         self._log("注册似乎完成了，但未能从 session 获取到正确的 access_token。", "error")
                         result.error_message = "没有在最终页面提取到 accessToken"
                         
                except Exception as ex:
                     self._log(f"解析 Session 时报错: {ex}", "error")
                     result.error_message = "解析 session 报错"
            
            except Exception as e:
                self._log(f"浏览器注册过程异常: {e}", "error")
                result.error_message = str(e)
            finally:
                browser.close()
                
        # To get the account ID, we might need a JWT decode or similar logic
        if result.success and result.access_token:
            from .register import _extract_account_id_from_jwt
            aid = _extract_account_id_from_jwt(result.access_token)
            if aid: result.account_id = aid
            
        return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        if not result.success: return False
        try:
            from ..config.settings import get_settings
            from ..database import crud
            from ..database.session import get_db
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
                self._log(f"浏览器注册账户已保存到数据库，ID: {account.id}")
                return True
        except Exception as e:
            self._log(f"保存到数据库失败: {e}", "error")
            return False
