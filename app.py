from flask import Flask, request
import jwt
import os
import requests
import json
import threading
import time
import logging

app = Flask(__name__)

# 配置日志
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s %(levelname)s: %(message)s')

# --- 配置您的凭证 ---
# App ID 和 App Secret Key 用于获取 Access Token
WIX_APP_ID = os.environ.get("WIX_APP_ID", "d6681108-ca66-4b33-8f4f-21e7652c1e5a")
WIX_APP_SECRET = os.environ.get("WIX_APP_SECRET", "29eb4f88-979f-4f14-9183-568dd1f9ef9c")

# 这是用于验证 Webhook JWT 的 Wix 公钥！
# 请替换为你在 Wix Dev Center 中找到的实际公钥
WIX_WEBHOOK_PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wBgf+mFx4Oy9SX5RKWJ
PTVBCFp8PtRlLiqtkieiGD3kf0HzWB6i/ZtFv/vIOGAXZitTJW4g+ZK/BzRj+BFx
GejYJmq9XRjMkHp+XKIvKjX2mTwgwQMJKvF4AEHT2reqdFzhyF4qWdRCxb2Jg1yF
klEnKE/HDuHekRMoNdtynPp6j5Dtql6AjyO+jx20JFWNco8XslHzyKzsynYrDmn3
BYIcD6UirXnG0N8dT9QJJxmGszoqf56QBrwmDzT2WvPvJxnhtMtP5EHSShs4NT3/
IVPtXMbIYgw4VqwSAiHG6yNQJKxrwYVyta02aCOqYbOC4/n51kSdz6xuez8mqf5f
QQIDAQAB
-----END PUBLIC KEY-----
"""

# 这是一个用于存储 instance_id 的简单字典，生产环境应使用数据库
app_instance_data = {}

# --- 辅助函数：获取 Access Token ---
# 此函数不需要修改，因为它使用 App ID 和 App Secret Key
def get_access_token(instance_id):
    url = "https://www.wixapis.com/oauth2/token"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "grant_type": "client_credentials",
        "client_id": WIX_APP_ID,
        "client_secret": WIX_APP_SECRET, # 这里仍然使用 App Secret Key
        "instance_id": instance_id
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))
        response.raise_for_status()

        token_info = response.json()
        app.logger.info(f"Successfully retrieved new access token for instance {instance_id}")
        return token_info.get("access_token")

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Failed to get access token from Wix API: {e}")
        if 'response' in locals() and hasattr(response, 'text'):
            app.logger.error(f"Wix API response content: {response.text}")
        return None

# --- Webhook 处理路由 ---
@app.route('/wix-webhook', methods=['POST'])
def handle_wix_webhook():
    jwt_token = request.data.decode('utf-8')
    app.logger.info("Received a new webhook request from Wix.")
    app.logger.debug(f"Raw JWT token: {jwt_token}")

    try:
        # 使用 Wix 公钥验证并解码 JWT，算法指定为 RS256
        # 注意：这里使用 WIX_WEBHOOK_PUBLIC_KEY 来验证 JWT
        decoded_jwt = jwt.decode(jwt_token, WIX_WEBHOOK_PUBLIC_KEY, algorithms=["RS256"])
        app.logger.debug(f"Decoded JWT payload: {decoded_jwt}")

        # 提取 instance_id
        # Wix Webhook 的数据通常在 'data' 字段中，且可能是 JSON 字符串
        # 所以需要先解析 'data' 字段
        webhook_data_str = decoded_jwt.get('data')
        if not webhook_data_str:
            app.logger.warning("Webhook payload 'data' field is missing or empty.")
            return "Payload missing data field", 400

        webhook_data = json.loads(webhook_data_str) # 将数据解析为 JSON 对象
        instance_id = webhook_data.get('instanceId') # 从解析后的数据中获取 instanceId

        if instance_id:
            app_instance_data[instance_id] = {
                'instance_id': instance_id,
                'access_token': None,
                'expires_at': 0
            }
            app.logger.info(f"Webhook received! instance_id: {instance_id} has been saved.")

            token = get_access_token(instance_id)
            if token:
                app_instance_data[instance_id]['access_token'] = token
                app_instance_data[instance_id]['expires_at'] = time.time() + 14400

            return "Webhook processed successfully", 200

        else:
            app.logger.warning("instanceId not found in webhook payload after parsing 'data'.")
            return "Payload missing instanceId", 400

    except jwt.exceptions.InvalidSignatureError:
        app.logger.error("Invalid signature. JWT verification failed. Check WIX_WEBHOOK_PUBLIC_KEY.")
        return "Invalid signature", 401
    except json.JSONDecodeError as e:
        app.logger.exception(f"Failed to parse 'data' field as JSON: {e}")
        return "Invalid JSON in payload data", 400
    except Exception as e:
        app.logger.exception("An unhandled exception occurred during webhook processing.")
        return f"Internal Server Error: {str(e)}", 500

# --- 后台任务：刷新 Access Token ---
def token_refresher_task():
    while True:
        current_time = time.time()
        for instance_id, data in list(app_instance_data.items()):
            if data['access_token'] and data['expires_at'] - current_time < 3600:
                app.logger.info(f"Access token for {instance_id} is about to expire. Refreshing...")
                new_token = get_access_token(instance_id)
                if new_token:
                    data['access_token'] = new_token
                    data['expires_at'] = time.time() + 14400
        time.sleep(600)

# --- 主程序入口 ---
if __name__ == '__main__':
    refresher_thread = threading.Thread(target=token_refresher_task, daemon=True)
    refresher_thread.start()

    # 确保以管理员权限运行以绑定到 5101 端口 (如果不是 root 用户)
    # 如果你已经是 root 用户，则无需 'sudo'
    app.run(host='0.0.0.0', port=5101, debug=True)