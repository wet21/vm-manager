"""
PVE (Proxmox VE) API模块
用于管理虚机的状态和资源
"""

import logging
import requests
from urllib3.exceptions import InsecureRequestWarning

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


class PVEClient:
    """PVE API客户端"""

    def __init__(self, config):
        self.host = config['host']
        self.port = config['port']
        self.user = config['user']
        self.password = config['password']
        self.verify_ssl = config.get('verify_ssl', False)
        self.base_url = f"https://{self.host}:{self.port}"
        self.ticket = None
        self.csrf_token = None

    def _make_request(self, method, path, data=None, params=None):
        """发送API请求的通用方法"""
        url = f"{self.base_url}{path}"
        headers = {'Accept': 'application/json'}

        if self.ticket:
            headers['Cookie'] = f'PVEAuthCookie={self.ticket}'

        # 对于POST请求，添加CSRF Token
        if method == 'POST' and self.csrf_token:
            headers['CSRFPreventionToken'] = self.csrf_token

        try:
            response = requests.request(
                method=method,
                url=url,
                data=data,
                params=params,
                headers=headers,
                verify=self.verify_ssl,
                timeout=30
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"PVE API请求失败：{e}")
            raise

    def login(self):
        """登录PVE获取认证票据"""
        path = "/api2/json/access/ticket"
        data = {
            'username': self.user,
            'password': self.password
        }

        try:
            response = self._make_request('POST', path, data=data)
            if response.status_code == 200:
                result = response.json()
                if 'data' in result:
                    self.ticket = result['data']['ticket']
                    self.csrf_token = result['data']['CSRFPreventionToken']
                    logger.info(f"PVE登录成功：{self.host}")
                    return True
            logger.warning(f"PVE登录失败：状态码 {response.status_code}")
            return False
        except Exception as e:
            logger.error(f"PVE登录异常：{e}")
            return False

    def get_vms(self, retry=True):
        """获取所有虚机列表"""
        if not self.ticket:
            self.login()

        path = "/api2/json/nodes/{node}/qemu".format(node='Cloud-03')

        try:
            response = self._make_request('GET', path)
            if response.status_code == 200:
                result = response.json()
                vms = []
                for vm in result.get('data', []):
                    vms.append({
                        'vmid': vm.get('vmid'),
                        'name': vm.get('name'),
                        'status': vm.get('status'),
                        'cpu': vm.get('cpu'),
                        'maxcpu': vm.get('maxcpu'),
                        'mem': vm.get('mem'),
                        'maxmem': vm.get('maxmem'),
                        'disk': vm.get('disk'),
                        'maxdisk': vm.get('maxdisk'),
                        'uptime': vm.get('uptime'),
                        'template': vm.get('template'),
                        'qmpstatus': vm.get('qmpstatus'),
                    })
                logger.info(f"获取到 {len(vms)} 个虚机")
                return vms
            elif response.status_code == 401 and retry:
                # Ticket过期，重新登录并重试
                logger.warning("PVE认证票据过期，重新登录...")
                self.ticket = None
                self.csrf_token = None
                if self.login():
                    return self.get_vms(retry=False)
            logger.warning(f"获取虚机列表失败：状态码 {response.status_code}")
            return []
        except Exception as e:
            logger.error(f"获取虚机列表异常：{e}")
            return []

    def get_vm_status(self, vmid, retry=True):
        """获取指定虚机的详细状态"""
        if not self.ticket:
            self.login()

        node = 'Cloud-03'
        path = f"/api2/json/nodes/{node}/qemu/{vmid}/status/current"

        try:
            response = self._make_request('GET', path)
            if response.status_code == 200:
                result = response.json()
                if 'data' in result:
                    data = result['data']
                    return {
                        'vmid': vmid,
                        'status': data.get('status'),
                        'cpu': data.get('cpu'),
                        'memory': {
                            'used': data.get('mem'),
                            'max': data.get('maxmem'),
                            'usage_percent': round(data.get('mem', 0) / data.get('maxmem', 1) * 100, 2) if data.get('maxmem') else 0
                        },
                        'disk': {
                            'used': data.get('disk'),
                            'max': data.get('maxdisk'),
                            'usage_percent': round(data.get('disk', 0) / data.get('maxdisk', 1) * 100, 2) if data.get('maxdisk') else 0
                        },
                        'uptime': data.get('uptime'),
                        'balloon': data.get('balloon'),
                        'cpu_count': data.get('cpus'),
                    }
            elif response.status_code == 401 and retry:
                # Ticket过期，重新登录并重试
                logger.warning(f"PVE认证票据过期，重新登录... (vmid={vmid})")
                self.ticket = None
                self.csrf_token = None
                if self.login():
                    return self.get_vm_status(vmid, retry=False)
            return None
        except Exception as e:
            logger.error(f"获取虚机 {vmid} 状态异常：{e}")
            return None

    def vm_action(self, vmid, action, retry=True):
        """
        对虚机执行操作

        Args:
            vmid: 虚机ID
            action: 操作类型 (start/stop/shutdown/reboot/reset)
            retry: 是否在401时重试

        Returns:
            dict: {'success': True/False, 'message': '...'}
        """
        if not self.ticket:
            self.login()

        node = 'Cloud-03'

        # 操作映射
        actions = {
            'start': '/status/start',
            'stop': '/status/stop',      # 硬停止
            'shutdown': '/status/shutdown',  # 软关机
            'reboot': '/status/reboot',   # 软重启
            'reset': '/status/reset',     # 硬重启
        }

        if action not in actions:
            return {'success': False, 'message': f'未知操作：{action}'}

        path = f"/api2/json/nodes/{node}/qemu/{vmid}{actions[action]}"

        try:
            response = self._make_request('POST', path)
            if response.status_code in [200, 201]:
                logger.info(f"虚机 {vmid} 执行 {action} 成功")
                return {'success': True, 'message': f'操作 {action} 执行成功'}
            elif response.status_code == 401 and retry:
                # Ticket过期，重新登录并重试
                logger.warning(f"PVE认证票据过期，重新登录... (vmid={vmid}, action={action})")
                self.ticket = None
                self.csrf_token = None
                if self.login():
                    return self.vm_action(vmid, action, retry=False)
            else:
                error_msg = response.text
                logger.warning(f"虚机 {vmid} 执行 {action} 失败：{error_msg}")
                return {'success': False, 'message': f'操作失败：{error_msg}'}
        except Exception as e:
            logger.error(f"虚机 {vmid} 执行 {action} 异常：{e}")
            return {'success': False, 'message': f'操作异常：{str(e)}'}

    def get_vm_config(self, vmid, retry=True):
        """获取虚机配置信息"""
        if not self.ticket:
            self.login()

        node = 'Cloud-03'
        path = f"/api2/json/nodes/{node}/qemu/{vmid}/config"

        try:
            response = self._make_request('GET', path)
            if response.status_code == 200:
                result = response.json()
                if 'data' in result:
                    return {'success': True, 'config': result['data']}
            elif response.status_code == 401 and retry:
                # Ticket过期，重新登录并重试
                logger.warning(f"PVE认证票据过期，重新登录... (vmid={vmid})")
                self.ticket = None
                self.csrf_token = None
                if self.login():
                    return self.get_vm_config(vmid, retry=False)
            return {'success': False, 'message': '获取配置失败'}
        except Exception as e:
            logger.error(f"获取虚机 {vmid} 配置异常：{e}")
            return {'success': False, 'message': str(e)}

    def get_vms_by_horizon_user(self, user_sid, horizon_client):
        """
        根据Horizon用户获取其关联的PVE虚机

        Args:
            user_sid: 用户的SID
            horizon_client: HorizonClient实例

        Returns:
            list: 用户关联的虚机列表
        """
        try:
            # 获取用户在Horizon中的虚机
            horizon_machines = horizon_client.get_machines_by_user(user_sid)
            if not horizon_machines:
                logger.warning(f"用户 {user_sid} 在Horizon中没有关联的虚机")
                return []

            # 获取所有PVE虚机
            all_pve_vms = self.get_vms()
            if not all_pve_vms:
                return []

            # 提取Horizon虚机名称列表（标准化处理：去掉域名后缀）
            horizon_vm_names = set()
            for machine in horizon_machines:
                name = machine.get('name') or machine.get('machine_name') or machine.get('display_name')
                if name:
                    # 标准化：只保留主机名部分（去掉域名后缀）
                    # 例如: "win10-002.archmond.ltd" -> "win10-002"
                    hostname = name.lower().split('.')[0]
                    horizon_vm_names.add(hostname)

            logger.info(f"Horizon用户 {user_sid} 关联虚机名称（标准化后）: {horizon_vm_names}")

            # 过滤PVE虚机：只返回名称匹配的虚机
            user_vms = []
            for vm in all_pve_vms:
                vm_name = vm.get('name', '').lower()
                if vm_name in horizon_vm_names:
                    user_vms.append(vm)
                    logger.info(f"匹配到虚机: {vm.get('name')} (vmid: {vm.get('vmid')})")

            logger.info(f"用户 {user_sid} 最终匹配到 {len(user_vms)} 个PVE虚机")
            return user_vms

        except Exception as e:
            logger.error(f"获取用户关联PVE虚机异常：{e}")
            return []


def create_pve_client(config):
    """工厂函数：创建PVE客户端"""
    return PVEClient(config)