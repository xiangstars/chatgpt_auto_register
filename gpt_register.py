import json
import os
import re
import sys
import time
import uuid
import math
import random
import string
import secrets
import hashlib
import base64
import threading
import argparse
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass
from typing import Any, Dict, Optional
import urllib.parse
import urllib.request
import urllib.error

from curl_cffi import requests


# ==========================================
# 彩色输出
# ==========================================

class C:
    """ANSI color codes for terminal output."""
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    CYAN    = "\033[36m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    BRED    = "\033[1;31m"   # Bold Red
    BGREEN  = "\033[1;32m"  # Bold Green
    BYELLOW = "\033[1;33m"  # Bold Yellow
    BCYAN   = "\033[1;36m"  # Bold Cyan


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_PARENT_DIR = os.path.dirname(PROJECT_DIR)
DATA_DIR = os.path.join(PROJECT_PARENT_DIR, "codexTokens")


def _to_int_with_min(value: Any, fallback: int, minimum: int = 1) -> int:
    """Best-effort int conversion with lower-bound guard."""
    try:
        return max(minimum, int(value))
    except Exception:
        return fallback


def _load_runtime_defaults() -> Dict[str, Any]:
    """
    Load CLI defaults from config.json and environment variables.
    Priority: env > config.json > hard-coded defaults.
    """
    defaults: Dict[str, Any] = {
        "proxy": None,
        "count": 10,
        "max_fail": 5,
        "sleep_min": 5,
        "sleep_max": 30,
    }

    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8-sig") as f:
                cfg = json.load(f)
            if isinstance(cfg, dict):
                cfg_proxy = str(cfg.get("proxy") or "").strip()
                defaults["proxy"] = cfg_proxy or None
                defaults["count"] = _to_int_with_min(cfg.get("total_accounts"), defaults["count"], minimum=1)
        except Exception as e:
            print(f"{C.YELLOW}[Warn] 读取 config.json 默认参数失败: {e}{C.RESET}")

    env_proxy = str(os.environ.get("PROXY") or "").strip()
    env_total = os.environ.get("TOTAL_ACCOUNTS")
    env_max_fail = os.environ.get("MAX_FAIL")
    env_sleep_min = os.environ.get("SLEEP_MIN")
    env_sleep_max = os.environ.get("SLEEP_MAX")

    if env_proxy:
        defaults["proxy"] = env_proxy
    if env_total is not None:
        defaults["count"] = _to_int_with_min(env_total, defaults["count"], minimum=1)
    if env_max_fail is not None:
        defaults["max_fail"] = _to_int_with_min(env_max_fail, defaults["max_fail"], minimum=1)
    if env_sleep_min is not None:
        defaults["sleep_min"] = _to_int_with_min(env_sleep_min, defaults["sleep_min"], minimum=1)
    if env_sleep_max is not None:
        defaults["sleep_max"] = _to_int_with_min(env_sleep_max, defaults["sleep_max"], minimum=1)

    return defaults

# ==========================================
# Mail.tm 临时邮箱 API
# ==========================================

MAILTM_BASE = "https://api.mail.tm"


def _mailtm_headers(*, token: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _mailtm_domains(proxies: Any = None) -> list[str]:
    resp = requests.get(
        f"{MAILTM_BASE}/domains",
        headers=_mailtm_headers(),
        proxies=proxies,
        impersonate="chrome",
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"获取 Mail.tm 域名失败，状态码: {resp.status_code}")

    data = resp.json()
    domains = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("hydra:member") or data.get("items") or []
    else:
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip()
        is_active = item.get("isActive", True)
        is_private = item.get("isPrivate", False)
        if domain and is_active and not is_private:
            domains.append(domain)

    return domains


def get_email_and_token(proxies: Any = None) -> tuple[str, str]:
    """创建 Mail.tm 邮箱并获取 Bearer Token"""
    try:
        domains = _mailtm_domains(proxies)
        if not domains:
            print(f"{C.RED}[Error] Mail.tm 没有可用域名{C.RESET}")
            return "", ""
        domain = random.choice(domains)

        for _ in range(5):
            local = f"oc{secrets.token_hex(5)}"
            email = f"{local}@{domain}"
            password = secrets.token_urlsafe(18)

            create_resp = requests.post(
                f"{MAILTM_BASE}/accounts",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )

            if create_resp.status_code not in (200, 201):
                continue

            token_resp = requests.post(
                f"{MAILTM_BASE}/token",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )

            if token_resp.status_code == 200:
                token = str(token_resp.json().get("token") or "").strip()
                if token:
                    return email, token

        print(f"{C.RED}[Error] Mail.tm 邮箱创建成功但获取 Token 失败{C.RESET}")
        return "", ""
    except Exception as e:
        print(f"{C.RED}[Error] 请求 Mail.tm API 出错: {e}{C.RESET}")
        return "", ""


def get_oai_code(token: str, email: str, proxies: Any = None) -> str:
    """使用 Mail.tm Token 轮询获取 OpenAI 验证码"""
    url_list = f"{MAILTM_BASE}/messages"
    regex = r"(?<!\d)(\d{6})(?!\d)"
    seen_ids: set[str] = set()

    print(f"{C.CYAN}[*] 正在等待邮箱 {email} 的验证码...{C.RESET}", end="", flush=True)

    for _ in range(40):
        print(".", end="", flush=True)
        try:
            resp = requests.get(
                url_list,
                headers=_mailtm_headers(token=token),
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue

            data = resp.json()
            if isinstance(data, list):
                messages = data
            elif isinstance(data, dict):
                messages = data.get("hydra:member") or data.get("messages") or []
            else:
                messages = []

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                read_resp = requests.get(
                    f"{MAILTM_BASE}/messages/{msg_id}",
                    headers=_mailtm_headers(token=token),
                    proxies=proxies,
                    impersonate="chrome",
                    timeout=15,
                )
                if read_resp.status_code != 200:
                    continue

                mail_data = read_resp.json()
                sender = str(
                    ((mail_data.get("from") or {}).get("address") or "")
                ).lower()
                subject = str(mail_data.get("subject") or "")
                intro = str(mail_data.get("intro") or "")
                text = str(mail_data.get("text") or "")
                html = mail_data.get("html") or ""
                if isinstance(html, list):
                    html = "\n".join(str(x) for x in html)
                content = "\n".join([subject, intro, text, str(html)])

                if "openai" not in sender and "openai" not in content.lower():
                    continue

                m = re.search(regex, content)
                if m:
                    print(f" {C.BGREEN}抓到啦! 验证码: {m.group(1)}{C.RESET}")
                    return m.group(1)
        except Exception:
            pass

        time.sleep(3)

    print(f" {C.RED}超时，未收到验证码{C.RESET}")
    return ""


# ==========================================
# OAuth 授权与辅助函数
# ==========================================

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

DEFAULT_REDIRECT_URI = f"http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _post_form(url: str, data: Dict[str, str], timeout: int = 30) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.status != 200:
                raise RuntimeError(
                    f"token exchange failed: {resp.status}: {raw.decode('utf-8', 'replace')}"
                )
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(
            f"token exchange failed: {exc.code}: {raw.decode('utf-8', 'replace')}"
        ) from exc


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_url(
    *, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE
) -> OAuthStart:
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )


def submit_callback_url(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())

    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
    )

    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    expires_in = _to_int(token_resp.get("expires_in"))

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now = int(time.time())
    expired_rfc3339 = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
    )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }

    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


# ==========================================
# 核心注册逻辑
# ==========================================


def run(proxy: Optional[str]) -> Optional[str]:
    proxies: Any = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    s = requests.Session(proxies=proxies, impersonate="chrome")

    try:
        trace = s.get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
        trace = trace.text
        loc_re = re.search(r"^loc=(.+)$", trace, re.MULTILINE)
        loc = loc_re.group(1) if loc_re else None
        print(f"{C.CYAN}[*] 当前 IP 所在地: {loc}{C.RESET}")
        if loc == "CN" or loc == "HK":
            raise RuntimeError("检查代理哦w - 所在地不支持")
    except Exception as e:
        print(f"{C.RED}[Error] 网络连接检查失败: {e}{C.RESET}")
        if proxy:
            print(f"{C.YELLOW}[Hint] 当前代理: {proxy}，请确认代理程序在线且可访问外网。{C.RESET}")
        else:
            print(f"{C.YELLOW}[Hint] 当前未设置代理。可用 --proxy 或在 config.json 配置 proxy。{C.RESET}")
        return None

    email, dev_token = get_email_and_token(proxies)
    if not email or not dev_token:
        return None
    print(f"{C.GREEN}[*] 成功获取 Mail.tm 邮箱与授权: {email}{C.RESET}")

    oauth = generate_oauth_url()
    url = oauth.auth_url

    try:
        resp = s.get(url, timeout=15)
        did = s.cookies.get("oai-did")
        print(f"{C.CYAN}[*] Device ID: {did}{C.RESET}")

        signup_body = f'{{"username":{{"value":"{email}","kind":"email"}},"screen_hint":"signup"}}'
        sen_req_body = f'{{"p":"","id":"{did}","flow":"authorize_continue"}}'

        sen_resp = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "origin": "https://sentinel.openai.com",
                "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                "content-type": "text/plain;charset=UTF-8",
            },
            data=sen_req_body,
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )

        if sen_resp.status_code != 200:
            print(f"{C.RED}[Error] Sentinel 异常拦截，状态码: {sen_resp.status_code}{C.RESET}")
            return None

        sen_token = sen_resp.json()["token"]
        sentinel = f'{{"p": "", "t": "", "c": "{sen_token}", "id": "{did}", "flow": "authorize_continue"}}'

        signup_resp = s.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "referer": "https://auth.openai.com/create-account",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel,
            },
            data=signup_body,
        )
        if signup_resp.status_code != 200:
            print(f"{C.RED}[Error] 提交注册表单失败，状态码: {signup_resp.status_code}{C.RESET}")
            return None
        print(f"{C.GREEN}[*] 提交注册表单状态: {signup_resp.status_code}{C.RESET}")

        otp_resp = s.post(
            "https://auth.openai.com/api/accounts/passwordless/send-otp",
            headers={
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "application/json",
                "content-type": "application/json",
            },
        )
        if otp_resp.status_code != 200:
            print(f"{C.RED}[Error] 验证码发送失败，状态码: {otp_resp.status_code}{C.RESET}")
            return None
        print(f"{C.GREEN}[*] 验证码发送状态: {otp_resp.status_code}{C.RESET}")

        code = get_oai_code(dev_token, email, proxies)
        if not code:
            return None

        code_body = f'{{"code":"{code}"}}'
        code_resp = s.post(
            "https://auth.openai.com/api/accounts/email-otp/validate",
            headers={
                "referer": "https://auth.openai.com/email-verification",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=code_body,
        )
        if code_resp.status_code != 200:
            print(f"{C.RED}[Error] 验证码校验失败，状态码: {code_resp.status_code}{C.RESET}")
            return None
        print(f"{C.GREEN}[*] 验证码校验状态: {code_resp.status_code}{C.RESET}")

        create_account_body = '{"name":"Neo","birthdate":"2000-02-20"}'
        create_account_resp = s.post(
            "https://auth.openai.com/api/accounts/create_account",
            headers={
                "referer": "https://auth.openai.com/about-you",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=create_account_body,
        )
        create_account_status = create_account_resp.status_code

        if create_account_status != 200:
            print(f"{C.RED}[Error] 账户创建失败，状态码: {create_account_status}{C.RESET}")
            print(create_account_resp.text)
            return None
        print(f"{C.GREEN}[*] 账户创建状态: {create_account_status}{C.RESET}")

        auth_cookie = s.cookies.get("oai-client-auth-session")
        if not auth_cookie:
            print(f"{C.RED}[Error] 未能获取到授权 Cookie{C.RESET}")
            return None

        auth_json = _decode_jwt_segment(auth_cookie.split(".")[0])
        workspaces = auth_json.get("workspaces") or []
        if not workspaces:
            print(f"{C.RED}[Error] 授权 Cookie 里没有 workspace 信息{C.RESET}")
            return None
        workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
        if not workspace_id:
            print(f"{C.RED}[Error] 无法解析 workspace_id{C.RESET}")
            return None

        select_body = f'{{"workspace_id":"{workspace_id}"}}'
        select_resp = s.post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers={
                "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                "content-type": "application/json",
            },
            data=select_body,
        )

        if select_resp.status_code != 200:
            print(f"{C.RED}[Error] 选择 workspace 失败，状态码: {select_resp.status_code}{C.RESET}")
            print(select_resp.text)
            return None

        continue_url = str((select_resp.json() or {}).get("continue_url") or "").strip()
        if not continue_url:
            print(f"{C.RED}[Error] workspace/select 响应里缺少 continue_url{C.RESET}")
            return None

        current_url = continue_url
        for _ in range(6):
            final_resp = s.get(current_url, allow_redirects=False, timeout=15)
            location = final_resp.headers.get("Location") or ""

            if final_resp.status_code not in [301, 302, 303, 307, 308]:
                break
            if not location:
                break

            next_url = urllib.parse.urljoin(current_url, location)
            if "code=" in next_url and "state=" in next_url:
                return submit_callback_url(
                    callback_url=next_url,
                    code_verifier=oauth.code_verifier,
                    redirect_uri=oauth.redirect_uri,
                    expected_state=oauth.state,
                )
            current_url = next_url

        print(f"{C.RED}[Error] 未能在重定向链中捕获到最终 Callback URL{C.RESET}")
        return None

    except Exception as e:
        print(f"{C.RED}[Error] 运行时发生错误: {e}{C.RESET}")
        return None


def main() -> None:
    defaults = _load_runtime_defaults()

    parser = argparse.ArgumentParser(description="OpenAI 自动注册脚本")
    parser.add_argument(
        "--proxy", default=defaults["proxy"], help="代理地址，如 http://127.0.0.1:7897"
    )
    parser.add_argument(
        "--count", "-n", type=int, default=defaults["count"], help="批量注册数量"
    )
    parser.add_argument(
        "--max-fail", type=int, default=defaults["max_fail"], help="连续失败次数上限，达到后终止并提醒换代理"
    )
    parser.add_argument("--sleep-min", type=int, default=defaults["sleep_min"], help="循环模式最短等待秒数")
    parser.add_argument(
        "--sleep-max", type=int, default=defaults["sleep_max"], help="循环模式最长等待秒数"
    )
    args = parser.parse_args()

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)
    target_count = max(1, args.count)
    max_consecutive_fail = max(1, args.max_fail)

    # 确保输出目录存在
    os.makedirs(DATA_DIR, exist_ok=True)

    success_count = 0
    attempt_count = 0
    consecutive_fail = 0

    print(f"{C.BCYAN}[Info] Yasal's Seamless OpenAI Auto-Registrar Started for ZJH{C.RESET}")
    print(f"{C.CYAN}[Info] 目标注册数量: {target_count}  |  连续失败上限: {max_consecutive_fail}{C.RESET}")
    if args.proxy:
        print(f"{C.CYAN}[Info] 使用代理: {args.proxy}{C.RESET}")
    else:
        print(f"{C.YELLOW}[Warn] 未配置代理，将尝试直连（在部分地区大概率失败）{C.RESET}")

    while success_count < target_count:
        attempt_count += 1
        print(
            f"\n{C.BOLD}[{datetime.now().strftime('%H:%M:%S')}] >>> 第 {attempt_count} 次尝试 "
            f"(成功 {C.GREEN}{success_count}{C.RESET}{C.BOLD}/{target_count}) <<<{C.RESET}"
        )

        try:
            token_json = run(args.proxy)

            if token_json:
                consecutive_fail = 0
                success_count += 1

                try:
                    t_data = json.loads(token_json)
                    fname_email = t_data.get("email", "unknown").replace("@", "_")
                except Exception:
                    fname_email = "unknown"

                file_name = os.path.join(DATA_DIR, f"token_{fname_email}_{int(time.time())}.json")

                with open(file_name, "w", encoding="utf-8") as f:
                    f.write(token_json)

                print(f"{C.BGREEN}[✓] 成功! Token 已保存至: {file_name}  ({success_count}/{target_count}){C.RESET}")
            else:
                consecutive_fail += 1
                print(f"{C.YELLOW}[-] 本次注册失败。(连续失败 {consecutive_fail}/{max_consecutive_fail}){C.RESET}")

        except Exception as e:
            consecutive_fail += 1
            print(f"{C.RED}[Error] 发生未捕获异常: {e}{C.RESET}")

        # 连续失败达到上限，终止程序
        if consecutive_fail >= max_consecutive_fail:
            print(f"\n{C.BRED}{'='*60}")
            print(f"[!] 连续失败 {consecutive_fail} 次，已达上限！")
            print(f"[!] 请更换代理 IP 后重试！")
            print(f"{'='*60}{C.RESET}")
            sys.exit(1)

        # 已达目标数量则退出
        if success_count >= target_count:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        print(f"{C.CYAN}[*] 休息 {wait_time} 秒...{C.RESET}")
        time.sleep(wait_time)

    print(f"\n{C.BGREEN}{'='*60}")
    print(f"[✓] 全部完成! 成功注册 {success_count} 个账号")
    print(f"[✓] Token 文件保存在: {os.path.abspath(DATA_DIR)}/")
    print(f"{'='*60}{C.RESET}")


if __name__ == "__main__":
    main()
