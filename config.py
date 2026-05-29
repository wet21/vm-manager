"""
配置文件 - 集中管理所有服务器配置
"""

# AD域配置
AD_CONFIG = {
    'host': '192.168.11.5',
    'port': 389,
    'use_ssl': False,
    # 格式：使用UPN格式 administrator@archmond.ltd 或完整DN格式 CN=Administrator,CN=Users,DC=archmond,DC=ltd
    'user_dn': 'CN=Administrator,CN=Users,DC=archmond,DC=ltd',
    'password': 'Gibbs001!',
    'base_dn': 'DC=archmond,DC=ltd',
}

# PVE配置
PVE_CONFIG = {
    'host': '192.168.11.13',
    'port': 8006,
    'user': 'root@pam',  # 使用 root@pam 进行认证
    'password': 'Gibbs001!',
    'verify_ssl': False,
}

# Horizon配置
HORIZON_CONFIG = {
    'host': '192.168.11.6',
    'port': 443,
    'user': 'administrator',
    'password': 'Gibbs001!',
    'domain': 'archmond.ltd',
}

# Flask配置
FLASK_CONFIG = {
    'host': '0.0.0.0',
    'port': 5000,
    'debug': True,
    'secret_key': 'vm-manager-secret-key-change-in-production',
}

# 日志配置
LOG_CONFIG = {
    'level': 'INFO',
    'file': '/tmp/vm_manager.log',
}
