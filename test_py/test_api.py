"""DeepSeek API 连通性测试：验证 配置读取 + API 调用 全链路"""
import sys

from llm.client import LLMClient, LLMError
from llm.config import LLMConfigError, load_config

def main() -> int:
    print("[*] 读取配置(环境变量)...")
    try:
        config = load_config()
    except LLMConfigError as exc:
        print(f"[失败] 配置错误: {exc}", file=sys.stderr)
        return 1

    print(f"[*] base_url = {config.base_url}")
    print(f"[*] model    = {config.model}")
    masked = config.api_key[:6] + "..." + config.api_key[-4:]
    print(f"[*] api_key  = {masked} (已脱敏)")

    print("[*] 发送测试请求...")
    client = LLMClient(config)
    try:
        resp = client.chat([
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user",
             "content": "请用 JSON 格式回复一个状态对象，例如: "
                        '{"status": "ok", "message": "DeepSeek API 连通成功"}'},
        ])
    except LLMError as exc:
        print(f"[失败] API 调用异常: {exc}", file=sys.stderr)
        return 1

    print(f"[成功] API 连通，模型返回:")
    print(resp)
    return 0

if __name__ == "__main__":
    sys.exit(main())