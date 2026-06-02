"""
AD域认证模块
使用ldap3库连接AD域进行用户鉴权
"""

import logging
import socket
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException

logger = logging.getLogger(__name__)

# LDAP连接超时时间（秒）
LDAP_CONNECT_TIMEOUT = 5


class ADAuthenticator:
    """AD域认证器"""

    def __init__(self, config):
        self.config = config
        self.server = None

    def _get_server(self):
        """创建LDAP服务器连接"""
        if self.server is None:
            self.server = Server(
                self.config['host'],
                port=self.config['port'],
                use_ssl=self.config['use_ssl'],
                get_info=ALL,
                connect_timeout=LDAP_CONNECT_TIMEOUT
            )
        return self.server

    def authenticate(self, username, password):
        """
        验证用户凭据

        Args:
            username: 用户名（可以是 sAMAccountName 或 user@domain格式）
            password: 密码

        Returns:
            dict: {'success': True, 'user_info': {...}} 或 {'success': False, 'error': '...'}
        """
        # 构建用户DN
        # 尝试查找用户的完整DN
        user_dn = self._find_user_dn(username)
        if not user_dn:
            return {'success': False, 'error': '用户不存在'}

        try:
            server = self._get_server()
            conn = Connection(
                server,
                user=user_dn,
                password=password,
                auto_bind=True,
                receive_timeout=LDAP_CONNECT_TIMEOUT
            )

            # 获取用户详细信息
            user_info = self._get_user_info(conn, user_dn)

            conn.unbind()
            logger.info(f"用户 {username} 认证成功")
            return {'success': True, 'user_info': user_info}

        except (LDAPException, socket.timeout, ConnectionError) as e:
            error_msg = str(e)
            if 'INVALID_CREDENTIALS' in error_msg.upper():
                logger.warning(f"用户 {username} 认证失败：密码错误")
                return {'success': False, 'error': '用户名或密码错误'}
            logger.error(f"LDAP认证异常：{e}")
            return {'success': False, 'error': f'认证异常：{error_msg}'}

    def _find_user_dn(self, username):
        """根据用户名查找用户的完整DN"""
        try:
            server = self._get_server()
            # 使用配置中的管理员账号进行搜索
            conn = Connection(
                server,
                user=self.config['user_dn'],
                password=self.config['password'],
                auto_bind=True,
                receive_timeout=LDAP_CONNECT_TIMEOUT
            )

            # 构建搜索过滤器
            # 支持多种用户名格式
            if '@' in username:
                # user@domain.com 格式
                search_name = username.split('@')[0]
            else:
                search_name = username

            search_filter = f'(|(sAMAccountName={search_name})(userPrincipalName={username}))'

            conn.search(
                search_base=self.config['base_dn'],
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['distinguishedName', 'sAMAccountName', 'displayName', 'memberOf']
            )

            if conn.entries:
                user_dn = str(conn.entries[0].distinguishedName)
                conn.unbind()
                return user_dn

            conn.unbind()
            return None

        except (LDAPException, socket.timeout, ConnectionError) as e:
            logger.error(f"搜索用户失败（连接AD服务器异常）：{type(e).__name__}: {e}")
            return None

    def _get_user_info(self, conn, user_dn):
        """获取用户详细信息"""
        try:
            conn.search(
                search_base=user_dn,
                search_filter='(objectClass=user)',
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'displayName', 'memberOf', 'department', 'title']
            )

            if conn.entries:
                entry = conn.entries[0]
                return {
                    'username': str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else '',
                    'display_name': str(entry.displayName) if hasattr(entry, 'displayName') else '',
                    'department': str(entry.department) if hasattr(entry, 'department') else '',
                    'title': str(entry.title) if hasattr(entry, 'title') else '',
                    'groups': [str(g) for g in entry.memberOf] if hasattr(entry, 'memberOf') else [],
                    'dn': user_dn
                }
        except Exception as e:
            logger.error(f"获取用户信息失败：{e}")

        return {'dn': user_dn}

    def get_user_groups(self, username):
        """获取用户所属的安全组"""
        user_dn = self._find_user_dn(username)
        if not user_dn:
            return []

        try:
            server = self._get_server()
            conn = Connection(
                server,
                user=self.config['user_dn'],
                password=self.config['password'],
                auto_bind=True,
                receive_timeout=LDAP_CONNECT_TIMEOUT
            )

            conn.search(
                search_base=user_dn,
                search_filter='(objectClass=user)',
                search_scope=SUBTREE,
                attributes=['memberOf']
            )

            if conn.entries and hasattr(conn.entries[0], 'memberOf'):
                groups = [str(g) for g in conn.entries[0].memberOf]
                conn.unbind()
                return groups

            conn.unbind()
        except (LDAPException, socket.timeout, ConnectionError) as e:
            logger.error(f"获取用户组失败：{type(e).__name__}: {e}")

        return []


def create_authenticator(config):
    """工厂函数：创建认证器实例"""
    return ADAuthenticator(config)