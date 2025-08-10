from flask import Flask, request
import jwt
import os
import requests
import json
import threading
import time
import logging # 导入 logging 模块

app = Flask(__name__)

# 配置日志，以便在控制台看到详细的错误信息
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s %(levelname)s: %(message)s')

# --- 配置您的凭证（请使用环境变量）---
# 在生产环境中，请不要将密钥直接写在代码中！
WIX_APP_ID = os.environ.get("WIX_APP_ID", "YOUR_APP_ID")
WIX_APP_SECRET = os.environ.get("WIX_APP_SECRET", "YOUR_APP_SECRET")
# 这是一个用于存储 instance_id 的简单字典，生产环境应使用数据库
app_instance_data = {}

# --- 辅助函数：获取 Access Token ---
def get_access_token(instance_id):
    """
    使用 instance_id 和其他凭证请求 Access Token
    """
    url = "https://www.wixapis.com/oauth2/token"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "grant_type": "client_credentials",
        "client_id": WIX_APP_ID,
        "client_secret": WIX_APP_SECRET,
        "instance_id": instance_id
    }
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))
        response.raise_for_status()  # 如果请求失败，抛出异常
        
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
    """
    处理来自 Wix 的 App Instance Installed webhook。
    """
    jwt_token = request.data.decode('utf-8')
    app.logger.info("Received a new webhook request from Wix.")
    app.logger.debug(f"Raw JWT token: {jwt_token}")
    
    try:
        # 使用 App Secret 验证并解码 JWT
        decoded_jwt = jwt.decode(jwt_token, WIX_APP_SECRET, algorithms=["HS256"])
        app.logger.debug(f"Decoded JWT payload: {decoded_jwt}")
        
        # 提取 instance_id
        instance_id = decoded_jwt.get('instanceId')
        
        if instance_id:
            # 将 instance_id 保存到我们的存储中
            app_instance_data[instance_id] = {
                'instance_id': instance_id,
                'access_token': None,
                'expires_at': 0
            }
            app.logger.info(f"Webhook received! instance_id: {instance_id} has been saved.")
            
            # 立即为这个实例获取 access token
            token = get_access_token(instance_id)
            if token:
                app_instance_data[instance_id]['access_token'] = token
                # 假设 token 有效期是 4 小时 (14400秒)
                app_instance_data[instance_id]['expires_at'] = time.time() + 14400
            
            return "Webhook processed successfully", 200
        
        else:
            app.logger.warning("instanceId not found in webhook payload.")
            return "Payload missing instanceId", 400
            
    except jwt.exceptions.InvalidSignatureError:
        app.logger.error("Invalid signature. JWT verification failed.")
        return "Invalid signature", 401
    except Exception as e:
        # 记录完整的堆栈跟踪，这是关键！
        app.logger.exception("An unhandled exception occurred during webhook processing.")
        return f"Internal Server Error: {str(e)}", 500

# --- 后台任务：刷新 Access Token ---
def token_refresher_task():
    """
    一个后台线程，负责检查并刷新即将过期的 access token。
    """
    while True:
        current_time = time.time()
        for instance_id, data in list(app_instance_data.items()):
            # 在 token 过期前一小时刷新
            if data['access_token'] and data['expires_at'] - current_time < 3600:
                print(f"Access token for {instance_id} is about to expire. Refreshing...")
                new_token = get_access_token(instance_id)
                if new_token:
                    data['access_token'] = new_token
                    data['expires_at'] = time.time() + 14400 # 更新过期时间
        time.sleep(600)  # 每 10 分钟检查一次

# --- 主程序入口 ---
if __name__ == '__main__':
    # 启动后台刷新任务
    refresher_thread = threading.Thread(target=token_refresher_task, daemon=True)
    refresher_thread.start()
    
    # 在生产环境中，应使用 Gunicorn 或 uWSGI
    # 这里使用 Flask 自带的服务器仅用于本地测试
    app.run(host='0.0.0.0', port=5101, debug=True)