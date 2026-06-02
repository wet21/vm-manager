"""
ARCHMOND云电脑自维护平台 - 主应用
基于Flask Web框架，提供用户认证和虚机管理功能
"""

import os
import sys
import logging
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, redirect, url_for

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import AD_CONFIG, PVE_CONFIG, HORIZON_CONFIG, FLASK_CONFIG
from auth.ldap_auth import ADAuthenticator
from api.pve_api import PVEClient
from api.horizon_api import HorizonClient

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/vm_manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 创建Flask应用
app = Flask(__name__)
app.secret_key = FLASK_CONFIG['secret_key']

# 初始化各服务的客户端
ad_auth = ADAuthenticator(AD_CONFIG)
pve_client = PVEClient(PVE_CONFIG)
horizon_client = HorizonClient(HORIZON_CONFIG)


# ==================== 辅助函数 ====================

def format_uptime(seconds):
    """格式化运行时间"""
    if not seconds:
        return 'N/A'
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    if days > 0:
        return f'{days}天 {hours}小时'
    elif hours > 0:
        return f'{hours}小时 {minutes}分钟'
    else:
        return f'{minutes}分钟'


def format_bytes(bytes_value):
    """格式化字节大小"""
    if not bytes_value:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024:
            return f'{bytes_value:.2f} {unit}'
        bytes_value /= 1024
    return f'{bytes_value:.2f} PB'


def get_user_sid(username):
    """通过LDAP获取用户的SID"""
    try:
        from ldap3 import Server, Connection, ALL
        server = Server(AD_CONFIG['host'], get_info=ALL, port=AD_CONFIG.get('port', 389))
        conn = Connection(server, user=AD_CONFIG['user_dn'], password=AD_CONFIG['password'], auto_bind=True)
        
        # 搜索用户
        conn.search(AD_CONFIG['base_dn'], f'(sAMAccountName={username})', search_scope=2, attributes=['objectSid'])
        
        if conn.entries:
            sid = conn.entries[0].objectSid.value
            logger.info(f"获取用户 {username} 的 SID: {sid}")
            conn.unbind()
            return sid
        
        conn.unbind()
        logger.warning(f"未找到用户 {username} 的 SID")
        return None
    except Exception as e:
        logger.error(f"获取用户 SID 失败：{e}")
        return None


# ==================== 认证装饰器 ====================

def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """管理员权限装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        if not session.get('is_admin', False):
            return jsonify({'success': False, 'message': '需要管理员权限'}), 403
        return f(*args, **kwargs)
    return decorated_function


# ==================== 页面路由 ====================

@app.route('/')
def index():
    """首页/登录页"""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login_page'))


@app.route('/login')
def login_page():
    """登录页面"""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """仪表盘页面"""
    return render_template('index.html',
                          user=session.get('user'),
                          display_name=session.get('display_name', session.get('user')))


# ==================== API接口 ====================

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """用户登录API"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'message': '用户名和密码不能为空'})

    # AD域认证
    result = ad_auth.authenticate(username, password)
    if result['success']:
        user_info = result['user_info']
        # 检查是否是管理员（可以根据AD组来判定）
        is_admin = any('Administrators' in g or 'Domain Admins' in g for g in user_info.get('groups', []))

        # 获取用户 SID 并存储到 session
        user_sid = get_user_sid(username)

        session['user'] = username
        session['display_name'] = user_info.get('display_name', username)
        session['is_admin'] = is_admin
        session['dn'] = user_info.get('dn', '')
        session['user_sid'] = user_sid

        logger.info(f"用户 {username} 登录成功，SID: {user_sid}")
        return jsonify({
            'success': True,
            'message': '登录成功',
            'data': {
                'username': username,
                'display_name': user_info.get('display_name', username),
                'is_admin': is_admin,
                'user_sid': user_sid
            }
        })
    else:
        logger.warning(f"用户 {username} 登录失败：{result['error']}")
        return jsonify({'success': False, 'message': result['error']})


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """用户登出API"""
    username = session.get('user', 'unknown')
    session.clear()
    logger.info(f"用户 {username} 已登出")
    return jsonify({'success': True, 'message': '已登出'})


@app.route('/api/auth/check', methods=['GET'])
def api_check_auth():
    """检查登录状态"""
    if 'user' in session:
        return jsonify({
            'success': True,
            'logged_in': True,
            'user': session.get('user'),
            'display_name': session.get('display_name'),
            'is_admin': session.get('is_admin', False),
            'user_sid': session.get('user_sid')
        })
    return jsonify({'success': True, 'logged_in': False})


# ==================== PVE虚机管理API ====================

@app.route('/api/pve/vms', methods=['GET'])
@login_required
def api_get_pve_vms():
    """获取PVE虚机列表（管理员返回所有，普通用户返回关联虚机）"""
    try:
        username = session.get('user')
        user_sid = session.get('user_sid')
        is_admin = session.get('is_admin', False)
        
        logger.info(f"用户 {username} 请求PVE虚机列表，管理员={is_admin}，SID={user_sid}")
        
        # 根据用户类型决定获取哪些虚机
        if is_admin:
            # 管理员：返回所有PVE虚机
            vms = pve_client.get_vms()
            logger.info(f"管理员 {username} 获取所有 {len(vms)} 台PVE虚机")
        else:
            # 普通用户：只返回与用户Horizon桌面对应的PVE虚机
            if not user_sid:
                user_sid = get_user_sid(username)
                session['user_sid'] = user_sid
            
            if user_sid:
                vms = pve_client.get_vms_by_horizon_user(user_sid, horizon_client)
                logger.info(f"用户 {username} (SID: {user_sid}) 获取到 {len(vms)} 台关联的PVE虚机")
            else:
                vms = []
                logger.warning(f"用户 {username} 无法获取SID，返回空列表")
        
        # 格式化数据
        formatted_vms = []
        for vm in vms:
            formatted_vms.append({
                'vmid': vm.get('vmid'),
                'name': vm.get('name', f'VM-{vm.get("vmid")}'),
                'status': vm.get('status', 'unknown'),
                'qmpstatus': vm.get('qmpstatus', 'unknown'),
                'cpu': {
                    'usage': vm.get('cpu', 0),
                    'count': vm.get('cpus', 1),
                },
                'memory': {
                    'used': format_bytes(vm.get('mem')),
                    'max': format_bytes(vm.get('maxmem')),
                    'raw_used': vm.get('mem', 0),
                    'raw_max': vm.get('maxmem', 0),
                },
                'disk': {
                    'used': format_bytes(vm.get('disk')),
                    'max': format_bytes(vm.get('maxdisk')),
                    'raw_used': vm.get('disk', 0),
                    'raw_max': vm.get('maxdisk', 0),
                },
                'uptime': format_uptime(vm.get('uptime')),
                'uptime_seconds': vm.get('uptime', 0),
                'is_template': vm.get('template', False),
                # 关联的Horizon桌面信息
                'horizon_name': vm.get('horizon_name'),
                'horizon_id': vm.get('horizon_id'),
                'horizon_state': vm.get('horizon_state'),
            })

        return jsonify({'success': True, 'vms': formatted_vms})
    except Exception as e:
        logger.error(f"获取PVE虚机列表异常：{e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/pve/vm/<int:vmid>/status', methods=['GET'])
@login_required
def api_get_vm_status(vmid):
    """获取指定虚机详细状态"""
    try:
        status = pve_client.get_vm_status(vmid)
        if status:
            # 格式化内存和磁盘显示
            status['memory']['used_fmt'] = format_bytes(status['memory']['used'])
            status['memory']['max_fmt'] = format_bytes(status['memory']['max'])
            status['uptime_fmt'] = format_uptime(status['uptime'])
            return jsonify({'success': True, 'status': status})
        return jsonify({'success': False, 'message': '获取状态失败'})
    except Exception as e:
        logger.error(f"获取虚机 {vmid} 状态异常：{e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/pve/vm/<int:vmid>/<action>', methods=['POST'])
@login_required
def api_vm_action(vmid, action):
    """执行虚机操作"""
    # 验证操作类型
    allowed_actions = ['start', 'stop', 'shutdown', 'reboot', 'reset']
    if action not in allowed_actions:
        return jsonify({'success': False, 'message': f'未知操作：{action}'})

    # 非管理员只能操作自己的虚机（这里简单处理，实际可根据用户-虚机映射来控制）
    if not session.get('is_admin', False):
        # 可以在这里添加用户和虚机的映射检查
        pass

    try:
        result = pve_client.vm_action(vmid, action)
        return jsonify(result)
    except Exception as e:
        logger.error(f"虚机 {vmid} 执行 {action} 异常：{e}")
        return jsonify({'success': False, 'message': str(e)})


# ==================== Horizon桌面管理API ====================

@app.route('/api/horizon/connect/<desktop_id>', methods=['GET'])
@login_required
def api_horizon_connect(desktop_id):
    """
    获取Horizon桌面连接URL（使用当前用户凭据登录）
    """
    try:
        username = session.get('user')
        password = session.get('horizon_password', '')
        
        if not password:
            return jsonify({
                'success': False, 
                'need_password': True,
                'message': '需要输入Horizon密码进行认证'
            }), 401
            
        # 使用用户凭据登录Horizon
        from api.horizon_api import HorizonClient
        temp_horizon = HorizonClient(HORIZON_CONFIG)
        temp_horizon.user = username
        temp_horizon.password = password
        temp_horizon.domain = 'archmond.ltd'
        
        if temp_horizon.login():
            access_token = temp_horizon.access_token
            connect_url = f"https://horizon.archmond.ltd/portal/webclient/#/launchitems"
            
            logger.info(f"用户 {username} 获取Horizon连接成功，desktop_id={desktop_id}")
            return jsonify({
                'success': True,
                'connect_url': connect_url,
                'access_token': access_token,
                'message': '认证成功，正在打开Horizon桌面...'
            })
        else:
            logger.warning(f"用户 {username} Horizon认证失败")
            return jsonify({'success': False, 'message': 'Horizon认证失败'}), 401
            
    except Exception as e:
        logger.error(f"获取Horizon连接异常：{e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/horizon/save-password', methods=['POST'])
@login_required
def api_save_horizon_password():
    """
    保存用户的Horizon密码到会话（用于后续自动连接）
    """
    try:
        data = request.get_json()
        password = data.get('password', '')
        username = session.get('user')
        
        if not password:
            return jsonify({'success': False, 'message': '密码不能为空'})
        
        # 验证密码是否正确（通过Horizon API）
        from api.horizon_api import HorizonClient
        temp_horizon = HorizonClient(HORIZON_CONFIG)
        temp_horizon.user = username
        temp_horizon.password = password
        temp_horizon.domain = 'archmond.ltd'
        
        if temp_horizon.login():
            # 密码验证成功，保存到会话
            session['horizon_password'] = password
            logger.info(f"用户 {username} 的Horizon密码验证成功，已保存到会话")
            return jsonify({'success': True, 'message': '密码验证成功'})
        else:
            logger.warning(f"用户 {username} 的Horizon密码验证失败")
            return jsonify({'success': False, 'message': '密码验证失败'})
            
    except Exception as e:
        logger.error(f"保存Horizon密码异常：{e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/horizon/desktops', methods=['GET'])
@login_required
def api_get_horizon_desktops():
    """获取Horizon桌面列表（根据当前用户过滤）"""
    try:
        username = session.get('user')
        user_sid = session.get('user_sid')
        
        logger.info(f"用户 {username} 请求 Horizon 桌面列表， SID: {user_sid}")
        
        # 如果没有 SID，尝试重新获取
        if not user_sid:
            user_sid = get_user_sid(username)
            session['user_sid'] = user_sid
        
        # 管理员可以看到所有桌面
        if session.get('is_admin', False):
            machines = horizon_client.get_machines()
            logger.info(f"管理员 {username} 获取所有 {len(machines)} 台虚机")
        else:
            # 非管理员只获取分配给自己的虚机
            if user_sid:
                machines = horizon_client.get_machines_by_user(user_sid)
                logger.info(f"用户 {username} (SID: {user_sid}) 获取到 {len(machines)} 台分配给自己的虚机")
            else:
                machines = []
                logger.warning(f"用户 {username} 无法获取 SID，返回空列表")
        
        return jsonify({'success': True, 'desktops': machines})
    except Exception as e:
        logger.error(f"获取Horizon桌面列表异常：{e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/horizon/desktop/<desktop_id>/<action>', methods=['POST'])
@login_required
def api_desktop_action(desktop_id, action):
    """执行Horizon桌面操作"""
    allowed_actions = ['start', 'stop', 'restart']
    if action not in allowed_actions:
        return jsonify({'success': False, 'message': f'未知操作：{action}'})

    # 检查用户是否有权限操作该桌面
    username = session.get('user')
    user_sid = session.get('user_sid')
    
    if not session.get('is_admin', False):
        # 非管理员只能操作分配给自己的桌面
        if user_sid:
            machines = horizon_client.get_machines_by_user(user_sid)
            machine_ids = [m.get('id') for m in machines]
            if desktop_id not in machine_ids:
                logger.warning(f"用户 {username} 试图操作未分配给自己的桌面 {desktop_id}")
                return jsonify({'success': False, 'message': '您没有权限操作此桌面'})

    try:
        result = horizon_client.desktop_action(desktop_id, action)
        return jsonify(result)
    except Exception as e:
        logger.error(f"桌面 {desktop_id} 执行 {action} 异常：{e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/horizon/sessions', methods=['GET'])
@login_required
def api_get_sessions():
    """获取Horizon会话列表"""
    try:
        sessions = horizon_client.get_sessions()
        return jsonify({'success': True, 'sessions': sessions})
    except Exception as e:
        logger.error(f"获取会话列表异常：{e}")
        return jsonify({'success': False, 'message': str(e)})


# ==================== 健康检查 ====================

@app.route('/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    return jsonify({'status': 'healthy', 'service': 'vm-manager'})


# ==================== 启动应用 ====================

if __name__ == '__main__':
    logger.info("=" * 50)
    logger.info("ARCHMOND云电脑自维护平台启动")
    logger.info(f"监听地址: {FLASK_CONFIG['host']}:{FLASK_CONFIG['port']}")
    logger.info("=" * 50)

    app.run(
        host=FLASK_CONFIG['host'],
        port=FLASK_CONFIG['port'],
        debug=FLASK_CONFIG['debug']
    )
