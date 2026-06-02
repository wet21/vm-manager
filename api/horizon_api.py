"""
VMware Horizon API模块
用于管理Horizon云桌面
"""

import logging
import requests
import json
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


class HorizonClient:
    """Horizon API客户端"""

    def __init__(self, config):
        self.host = config['host']
        self.port = config['port']
        self.user = config['user']
        self.password = config['password']
        self.domain = config.get('domain', 'archmond.ltd')
        self.base_url = f"https://{self.host}/rest"

        self.access_token = None
        self.refresh_token = None

    def _make_request(self, method, path, data=None, params=None, retry=False):
        """发送API请求的通用方法"""
        url = f"{self.base_url}{path}"
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        if self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'

        try:
            response = requests.request(
                method=method,
                url=url,
                data=json.dumps(data) if data else None,
                params=params,
                headers=headers,
                verify=False,
                timeout=30
            )

            # 如果是401未授权，且还没尝试过刷新token，则尝试刷新
            if response.status_code == 401 and not retry and self.refresh_token:
                logger.info("Access token过期，尝试刷新token...")
                if self._refresh_token():
                    # 刷新成功后重试原请求
                    return self._make_request(method, path, data, params, retry=True)
                else:
                    # 刷新失败，重新登录
                    logger.info("刷新token失败，重新登录...")
                    if self.login():
                        return self._make_request(method, path, data, params, retry=True)

            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Horizon API请求失败：{e}")
            raise

    def _refresh_token(self):
        """使用refresh_token刷新access_token"""
        path = "/refresh-token"
        data = {
            'refresh_token': self.refresh_token
        }

        try:
            # 不带Authorization header发送刷新请求
            url = f"{self.base_url}{path}"
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            response = requests.post(
                url=url,
                data=json.dumps(data),
                headers=headers,
                verify=False,
                timeout=30
            )
            if response.status_code == 200:
                result = response.json()
                self.access_token = result.get('access_token')
                if result.get('refresh_token'):
                    self.refresh_token = result.get('refresh_token')
                logger.info("Token刷新成功")
                return True
            logger.warning(f"Token刷新失败：状态码 {response.status_code}")
            return False
        except Exception as e:
            logger.error(f"Token刷新异常：{e}")
            return False

    def login(self):
        """登录Horizon API获取访问令牌"""
        path = "/login"
        data = {
            'domain': self.domain,
            'username': self.user,
            'password': self.password
        }

        try:
            # 尝试v1 API登录
            response = self._make_request('POST', path, data=data)
            if response.status_code == 200:
                result = response.json()
                self.access_token = result.get('access_token')
                self.refresh_token = result.get('refresh_token')
                logger.info(f"Horizon登录成功：{self.host}")
                return True
            return False
        except Exception as e:
            logger.error(f"Horizon登录异常：{e}")
            return False

    def get_desktops(self):
        """获取所有桌面池/虚机列表"""
        if not self.access_token:
            self.login()

        path = "/inventory/v1/machines"

        try:
            response = self._make_request('GET', path)
            if response.status_code == 200:
                result = response.json()
                desktops = []
                # 处理API返回不同格式的情况
                values = result.get('values') if isinstance(result, dict) else result
                for desk in (values or []):
                    desktops.append({
                        'id': desk.get('id'),
                        'name': desk.get('name'),
                        'type': desk.get('type'),
                        'state': desk.get('state'),
                        'source': desk.get('source'),
                        'user_ids': desk.get('user_ids') or [],
                    })
                logger.info(f"获取到 {len(desktops)} 个桌面")
                return desktops
            logger.warning(f"获取桌面列表失败：状态码 {response.status_code}")
            return []
        except Exception as e:
            logger.error(f"获取桌面列表异常：{e}")
            return []

    def get_machines(self):
        """
        获取所有桌面/虚机列表（get_desktops的别名）
        解决 app.py 调用 get_machines() 但方法名不一致的问题
        """
        return self.get_desktops()

    def get_desktop_states(self):
        """获取桌面状态"""
        if not self.access_token:
            self.login()

        path = "/inventory/v1/desktop-states"

        try:
            response = self._make_request('GET', path)
            if response.status_code == 200:
                result = response.json()
                return result.get('values', [])
            return []
        except Exception as e:
            logger.error(f"获取桌面状态异常：{e}")
            return []

    def get_sessions(self):
        """获取当前会话列表"""
        if not self.access_token:
            self.login()

        path = "/inventory/v1/sessions"

        try:
            response = self._make_request('GET', path)
            if response.status_code == 200:
                result = response.json()
                sessions = []
                # 处理API返回不同格式的情况
                values = result.get('values') if isinstance(result, dict) else result
                for session in (values or []):
                    sessions.append({
                        'id': session.get('id'),
                        'username': session.get('user_name'),
                        'desktop_id': session.get('desktop_id'),
                        'state': session.get('state'),
                        'connected_date': session.get('connected_date'),
                    })
                return sessions
            return []
        except Exception as e:
            logger.error(f"获取会话列表异常：{e}")
            return []

    def desktop_action(self, desktop_id, action):
        """
        对桌面执行操作

        Args:
            desktop_id: 桌面ID
            action: 操作类型 (start/stop/restart)

        Returns:
            dict: {'success': True/False, 'message': '...'}
        """
        if not self.access_token:
            self.login()

        actions = {
            'start': '/start',
            'stop': '/stop',
            'restart': '/restart',
        }

        if action not in actions:
            return {'success': False, 'message': f'未知操作：{action}'}

        path = f"/inventory/v1/desktop-packages/{desktop_id}{actions[action]}"

        try:
            response = self._make_request('POST', path)
            if response.status_code in [200, 201, 202]:
                logger.info(f"桌面 {desktop_id} 执行 {action} 成功")
                return {'success': True, 'message': f'操作 {action} 执行成功'}
            else:
                error_msg = response.text
                logger.warning(f"桌面 {desktop_id} 执行 {action} 失败：{error_msg}")
                return {'success': False, 'message': f'操作失败：{error_msg}'}
        except Exception as e:
            logger.error(f"桌面 {desktop_id} 执行 {action} 异常：{e}")
            return {'success': False, 'message': f'操作异常：{str(e)}'}

    def force_logoff_session(self, session_id):
        """强制注销会话"""
        if not self.access_token:
            self.login()

        path = f"/inventory/v1/sessions/{session_id}/force-logoff"

        try:
            response = self._make_request('POST', path)
            if response.status_code in [200, 201, 202]:
                return {'success': True, 'message': '会话已强制注销'}
            return {'success': False, 'message': f'操作失败：{response.text}'}
        except Exception as e:
            return {'success': False, 'message': f'操作异常：{str(e)}'}

    def get_machines_by_user(self, user_sid):
        """
        根据用户SID获取该用户在Horizon上分配的桌面

        Args:
            user_sid: 用户的SID (如 S-1-5-21-...-1114)

        Returns:
            list: 用户关联的桌面列表，每项包含 id, name, state
        """
        if not self.access_token:
            self.login()

        # 直接通过user_ids字段匹配用户和桌面的关系
        desktops = self.get_desktops()
        logger.info(f"查询到 {len(desktops)} 个Horizon桌面")

        user_machines = []
        for desk in desktops:
            # desk的user_ids字段是包含用户SID的数组
            user_ids = desk.get('user_ids') or []
            if user_sid in user_ids:
                user_machines.append({
                    'id': desk.get('id'),
                    'name': desk.get('name'),
                    'state': desk.get('state', 'UNKNOWN'),
                })

        logger.info(f"用户 {user_sid} 关联 {len(user_machines)} 台Horizon桌面")
        return user_machines


def create_horizon_client(config):
    """工厂函数：创建Horizon客户端"""
    return HorizonClient(config)