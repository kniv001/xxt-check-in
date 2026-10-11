# -*- coding: utf-8 -*-
"""学习通签到助手 · 浏览器版(学生端)

用法:
  python server.py                 # 只绑本机 127.0.0.1,浏览器开 http://127.0.0.1:8787
  python server.py --lan           # 绑 0.0.0.0,供手机浏览器访问(打印带令牌的地址)
  python server.py --lan --port 9000

边界:仅学生端白名单接口(见 xxt_api.py);账号数据只存本机 data/accounts.json。
"""
import argparse
import base64
import json
import os
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, request, send_from_directory

import xxt_api as api

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, 'data')
ACC_FILE = os.path.join(DATA, 'accounts.json')

app = Flask(__name__, static_folder=os.path.join(ROOT, 'static'), static_url_path='/static')
ACCESS_TOKEN = None
lock = threading.RLock()

# ------------------------- 账号存储 -------------------------


def load_accounts():
    if not os.path.exists(ACC_FILE):
        return []
    try:
        return json.load(open(ACC_FILE, encoding='utf-8'))
    except Exception:
        return []


def save_accounts(lst):
    os.makedirs(DATA, exist_ok=True)
    json.dump(lst, open(ACC_FILE, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)


# ------------------------- HTTPS(本地 CA + 服务器证书) -------------------------

CERT_DIR = os.path.join(ROOT, 'certs')


def _local_ips():
    """本机全部可用地址(默认路由出口优先)"""
    import socket
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('223.5.5.5', 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    for fam, probe in ((socket.AF_INET, None), (socket.AF_INET6, None)):
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, fam):
                ip = info[4][0]
                if ip.startswith('127.') or ip == '::1' or ip.split('%')[0] in ips:
                    continue
                if fam == socket.AF_INET6 and not ip.split('%')[0].startswith('2001:'):
                    continue                      # 只挑全球 IPv6,不带 link-local
                ips.append(ip.split('%')[0])
        except Exception:
            pass
    return ips


def ensure_certs():
    """生成/复用本地 CA 与本机服务器证书;返回 (cert_path, key_path)。

    - CA 一次生成长期复用:手机端装一次,之后换 IP 也不用重装;
    - 服务器证书 SAN=当前全部地址,IP 变化时自动重签。
    """
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    os.makedirs(CERT_DIR, exist_ok=True)
    ca_key_p = os.path.join(CERT_DIR, 'ca.key')
    ca_crt_p = os.path.join(CERT_DIR, 'ca.crt')
    srv_key_p = os.path.join(CERT_DIR, 'server.key')
    srv_crt_p = os.path.join(CERT_DIR, 'server.crt')
    san_mark = os.path.join(CERT_DIR, '.san')

    now = datetime.now(timezone.utc)
    if not (os.path.exists(ca_key_p) and os.path.exists(ca_crt_p)):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'xxt-web local CA')])
        ca = (x509.CertificateBuilder()
              .subject_name(name).issuer_name(name)
              .public_key(ca_key.public_key())
              .serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(days=1))
              .not_valid_after(now + timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
              .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                           key_encipherment=False, data_encipherment=False,
                                           key_agreement=False, key_cert_sign=True, crl_sign=True,
                                           encipher_only=False, decipher_only=False), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .sign(ca_key, hashes.SHA256()))
        open(ca_key_p, 'wb').write(ca_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        open(ca_crt_p, 'wb').write(ca.public_bytes(serialization.Encoding.PEM))

    sans = ['127.0.0.1', '::1', 'localhost'] + _local_ips()
    sans = sorted(set(sans))
    if (os.path.exists(san_mark) and os.path.exists(srv_crt_p) and os.path.exists(srv_key_p)
            and open(san_mark, encoding='utf-8').read().strip() == '\n'.join(sans)):
        return srv_crt_p, srv_key_p

    ca_key = serialization.load_pem_private_key(open(ca_key_p, 'rb').read(), password=None)
    ca_crt = x509.load_pem_x509_certificate(open(ca_crt_p, 'rb').read())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alt = []
    for s in sans:
        try:
            import ipaddress
            alt.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            alt.append(x509.DNSName(s))
    crt = (x509.CertificateBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'xxt-web')]))
           .issuer_name(ca_crt.subject)
           .public_key(key.public_key())
           .serial_number(x509.random_serial_number())
           .not_valid_before(now - timedelta(days=1))
           .not_valid_after(now + timedelta(days=3650))
           .add_extension(x509.SubjectAlternativeName(alt), critical=False)
           .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
           .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
           .sign(ca_key, hashes.SHA256()))
    open(srv_key_p, 'wb').write(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(srv_crt_p, 'wb').write(crt.public_bytes(serialization.Encoding.PEM))
    open(san_mark, 'w', encoding='utf-8').write('\n'.join(sans))
    return srv_crt_p, srv_key_p


def load_or_create_token():
    """持久化访问令牌(存 data/.token,重启不变,手机书签不用换)"""
    p = os.path.join(DATA, '.token')
    try:
        t = open(p, encoding='utf-8').read().strip()
        if len(t) >= 16:
            return t
    except Exception:
        pass
    t = secrets.token_hex(8)
    os.makedirs(DATA, exist_ok=True)
    open(p, 'w', encoding='utf-8').write(t)
    return t


def public_account(a):
    return {k: a.get(k) for k in ('id', 'uid', 'name', 'remark', 'phone', 'school', 'uname', 'expired')}


def find_account(acc_id):
    for a in load_accounts():
        if a['id'] == acc_id:
            return a
    return None


# ------------------------- 监测引擎 -------------------------

monitor = {
    'on': False, 'interval': 10, 'lastScan': '', 'entries': {}, 'exited': threading.Event(),
}
monitor_thread = None


def _merge_poll(results_by_acc, failed):
    """把一轮 activelist 结果合并进 monitor['entries']"""
    with lock:
        old = monitor['entries']
        fresh = {}
        for acc_id, (acc, entries) in results_by_acc.items():
            for e in entries:
                key = '%s#%s' % (acc_id, e['activeId'])
                prev = old.get(key)
                entry = dict(e)
                entry.update({'accId': acc_id,
                              'accName': acc.get('remark') or acc.get('name') or '账号',
                              'type': TYPES.get(e['otherId'], '普通签到'),
                              'isNew': prev is None})
                if prev:
                    entry['uid'] = prev.get('uid', '')
                    entry['signed'] = prev.get('signed', False)
                    entry['checked'] = prev.get('checked', False)
                    entry['state'] = '成功' if prev.get('state') == '成功' else prev.get('state', '待签')
                else:
                    entry['uid'] = ''
                    entry['signed'] = False
                    entry['checked'] = False
                    entry['state'] = '待签'
                fresh[key] = entry
        for key, prev in old.items():
            if key not in fresh and prev['accId'] in failed:
                fresh[key] = prev          # 拉取失败的账号保留旧条目
        monitor['entries'] = fresh
        monitor['lastScan'] = time.strftime('%H:%M:%S')
        return [k for k, v in fresh.items() if v.pop('isNew', False)]


TYPES = {'0': '普通签到', '1': '签到', '2': '二维码签到', '3': '手势签到',
         '4': '位置签到', '5': '签到码'}


def poll_once():
    accs = [a for a in load_accounts() if not a.get('expired') and a.get('cookie')]
    results, failed = {}, set()
    if not accs:
        with lock:
            monitor['lastScan'] = time.strftime('%H:%M:%S')
        return []

    def work(a):
        ok, msg, cj, entries = api.active_list(a['cookie'], a['ua'])
        return a, ok, entries

    with ThreadPoolExecutor(max_workers=8) as ex:
        for a, ok, entries in ex.map(work, accs):
            if ok:
                results[a['id']] = (a, entries)
            else:
                failed.add(a['id'])
    new_keys = _merge_poll(results, failed)

    # 未做页面态检查的:拉 preSign 判已签/未签 + 取页面 uid
    need = [e for e in list(monitor['entries'].values())
            if not e.get('checked') and e.get('courseId')]
    if need:
        acc_map = {a['id']: a for a in accs}

        def check(e):
            a = acc_map.get(e['accId'])
            if not a:
                return
            p = api.presign_page(a['cookie'], a['ua'], a['uid'],
                                 e['courseId'], e['classId'], e['activeId'])
            with lock:
                cur = monitor['entries'].get('%s#%s' % (e['accId'], e['activeId']))
                if cur:
                    cur['uid'] = p['uid']
                    cur['signed'] = p['signed']
                    cur['checked'] = p['ok']
                    cur['state'] = '已签' if p['signed'] else ('待签' if p['ok'] else '待签(页面拉取失败)')

        with ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(check, need))
    return new_keys


def monitor_loop():
    while not monitor['exited'].is_set():
        try:
            poll_once()
        except Exception as ex:
            print('[monitor] 轮询异常:', ex)
        monitor['exited'].wait(monitor['interval'])
    monitor['exited'].clear()


def set_entry_state(acc_id, active_id, state):
    with lock:
        e = monitor['entries'].get('%s#%s' % (acc_id, active_id))
        if e:
            e['state'] = state
            if state == '成功':
                e['signed'] = True


# ------------------------- 鉴权(仅 LAN 模式) -------------------------

@app.before_request
def auth_guard():
    if not ACCESS_TOKEN:
        return None
    if request.path.startswith('/static') or request.path == '/ca.crt':
        return None
    if request.remote_addr in ('127.0.0.1', '::1'):      # 本机回环免令牌
        return None
    k = request.args.get('k') or request.cookies.get('k')
    if k == ACCESS_TOKEN:
        return None
    return jsonify({'ok': False, 'msg': '缺少访问令牌(用启动时打印的带 ?k= 的地址打开)'}), 401


@app.after_request
def set_token_cookie(resp):
    if ACCESS_TOKEN and request.args.get('k') == ACCESS_TOKEN:
        resp.set_cookie('k', ACCESS_TOKEN, max_age=30 * 86400, samesite='Lax')
    return resp


# ------------------------- 页面 -------------------------

@app.get('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')


@app.get('/ca.crt')
def ca_file():
    """方便手机直接下载本地 CA(装机信任用)"""
    return send_from_directory(CERT_DIR, 'ca.crt', mimetype='application/x-x509-ca-cert')


# ------------------------- 账号 API -------------------------

@app.get('/api/accounts')
def list_accounts():
    return jsonify({'ok': True, 'accounts': [public_account(a) for a in load_accounts()]})


@app.post('/api/accounts/sendcode')
def sendcode():
    phone = (request.json or {}).get('phone', '').strip()
    if not re.match(r'^1\d{10}$', phone):
        return jsonify({'ok': False, 'msg': '手机号格式不对'})
    ok, msg = api.send_captcha(phone)
    return jsonify({'ok': ok, 'msg': msg})


@app.post('/api/accounts/login')
def login():
    d = request.json or {}
    remark, uname = d.get('remark', '').strip(), d.get('uname', '').strip()
    code, mode = d.get('code', '').strip(), d.get('mode', 'sms')
    if not (uname and code):
        return jsonify({'ok': False, 'msg': '账号与验证码/密码必填'})
    ua = api.gen_dalvik_ua()
    ok, msg, cookie = api.login(uname, code, is_sms=(mode == 'sms'), ua=ua)
    if not ok:
        return jsonify({'ok': False, 'msg': msg})
    info = api.sso_info(cookie, ua)
    if not info['valid']:
        return jsonify({'ok': False, 'msg': '档案校验失败,请重试'})
    acc = {'id': info['uid'], 'uid': info['uid'], 'name': info['name'] or info['nick'],
           'remark': remark or info['name'] or info['nick'], 'phone': info['phone'],
           'school': info['school'], 'uname': info['uname'], 'cookie': cookie, 'ua': ua,
           'expired': False}
    lst = load_accounts()
    for i, a in enumerate(lst):
        if a['id'] == acc['id']:
            lst[i] = acc
            break
    else:
        lst.append(acc)
    save_accounts(lst)
    return jsonify({'ok': True, 'msg': '账号已保存', 'account': public_account(acc)})


@app.post('/api/accounts/import')
def import_account():
    """从手机端 cookie 串导入(教师/学生复盘用;仅存本机)"""
    d = request.json or {}
    cookie = d.get('cookie', '').strip()
    if not cookie:
        return jsonify({'ok': False, 'msg': 'cookie 为空'})
    ua = d.get('ua') or api.gen_dalvik_ua()
    info = api.sso_info(cookie, ua)
    if not info['valid']:
        return jsonify({'ok': False, 'msg': '该 cookie 已失效'})
    acc = {'id': info['uid'], 'uid': info['uid'], 'name': info['name'] or info['nick'],
           'remark': d.get('remark') or info['name'] or info['nick'], 'phone': info['phone'],
           'school': info['school'], 'uname': info['uname'], 'cookie': cookie, 'ua': ua,
           'expired': False}
    lst = load_accounts()
    for i, a in enumerate(lst):
        if a['id'] == acc['id']:
            lst[i] = acc
            break
    else:
        lst.append(acc)
    save_accounts(lst)
    return jsonify({'ok': True, 'msg': '导入成功', 'account': public_account(acc)})


@app.post('/api/accounts/delete')
def delete_account():
    acc_id = (request.json or {}).get('id', '')
    save_accounts([a for a in load_accounts() if a['id'] != acc_id])
    return jsonify({'ok': True})


@app.post('/api/accounts/remark')
def remark_account():
    d = request.json or {}
    lst = load_accounts()
    for a in lst:
        if a['id'] == d.get('id'):
            a['remark'] = d.get('remark', '').strip()
    save_accounts(lst)
    return jsonify({'ok': True})


@app.post('/api/accounts/refresh')
def refresh_validity():
    def work(a):
        info = api.sso_info(a['cookie'], a['ua'])
        a['expired'] = not info['valid']
        return a

    lst = load_accounts()
    with ThreadPoolExecutor(max_workers=16) as ex:
        lst = list(ex.map(work, lst))
    save_accounts(lst)
    return jsonify({'ok': True, 'accounts': [public_account(a) for a in lst]})


# ------------------------- 监测 API -------------------------

@app.get('/api/detected')
def detected():
    with lock:
        return jsonify({'ok': True, 'monitoring': monitor['on'],
                        'interval': monitor['interval'], 'lastScan': monitor['lastScan'],
                        'entries': list(monitor['entries'].values())})


@app.post('/api/monitor')
def set_monitor():
    global monitor_thread
    d = request.json or {}
    if 'interval' in d:
        monitor['interval'] = max(5, min(60, int(d['interval'])))
    want = bool(d.get('on'))
    if want and not monitor['on']:
        monitor['on'] = True
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    elif not want and monitor['on']:
        monitor['on'] = False
        monitor['exited'].set()
    return jsonify({'ok': True, 'monitoring': monitor['on'], 'interval': monitor['interval']})


@app.post('/api/scan')
def scan_once():
    new_keys = poll_once()
    return jsonify({'ok': True, 'newKeys': new_keys, 'entries': list(monitor['entries'].values())})


# ------------------------- 签到 API -------------------------

def _uid_for(acc, e):
    """页面渲染 uid 优先(与 App 同策略);没有则回退账号 uid"""
    return e.get('uid') or acc['uid']


def _already_signed_guard(d, e):
    """已签守卫:页面判定已签则不再重复提交(force=true 可强制)"""
    if e.get('signed') and not d.get('force'):
        return jsonify({'ok': True, 'msg': '该活动已签到,无需重复提交'})
    return None


@app.post('/api/sign/normal')
def sign_normal():
    d = request.json or {}
    acc = find_account(d['accId'])
    e = monitor['entries'].get('%s#%s' % (d['accId'], d['activeId']))
    if not (acc and e):
        return jsonify({'ok': False, 'msg': '条目或账号不存在,请先扫描'})
    guard = _already_signed_guard(d, e)
    if guard:
        return guard
    body = api.submit_normal(acc['cookie'], acc['ua'], e['activeId'], e['courseId'], _uid_for(acc, e))
    ok, msg = api.classify(body)
    set_entry_state(d['accId'], d['activeId'], '成功' if ok else '失败: ' + msg)
    return jsonify({'ok': ok, 'msg': msg})


@app.post('/api/sign/qr')
def sign_qr():
    d = request.json or {}
    acc = find_account(d['accId'])
    e = monitor['entries'].get('%s#%s' % (d['accId'], d['activeId']))
    if not (acc and e):
        return jsonify({'ok': False, 'msg': '条目或账号不存在,请先扫描'})
    guard = _already_signed_guard(d, e)
    if guard:
        return guard
    text = d.get('text') or ''
    if d.get('image'):
        img = base64.b64decode(d['image'].split(',')[-1])
        text = api.decode_qr(img) or ''
        if not text:
            return jsonify({'ok': False, 'msg': '图片中未识别到二维码'})
    p = api.parse_qr_text(text)
    if not p['enc']:
        return jsonify({'ok': False, 'msg': '未能解出 enc,请换新码'})
    if p['id'] and p['id'] != e['activeId']:
        return jsonify({'ok': False, 'msg': '码属于活动 %s,与本条 %s 不符' % (p['id'], e['activeId'])})
    body = api.submit_qr(acc['cookie'], acc['ua'], e['activeId'], _uid_for(acc, e), p['enc'])
    ok, msg = api.classify(body)
    if not ok and '失效' in msg:
        msg += '(自动刷新码约 10 秒一换,请重新截图)'
    set_entry_state(d['accId'], d['activeId'], '成功' if ok else '失败: ' + msg)
    return jsonify({'ok': ok, 'msg': msg})


@app.post('/api/sign/location')
def sign_location():
    d = request.json or {}
    acc = find_account(d['accId'])
    e = monitor['entries'].get('%s#%s' % (d['accId'], d['activeId']))
    if not (acc and e):
        return jsonify({'ok': False, 'msg': '条目或账号不存在,请先扫描'})
    guard = _already_signed_guard(d, e)
    if guard:
        return guard
    if not d.get('address', '').strip():
        return jsonify({'ok': False, 'msg': '位置签需要地址文本(与页面一致,空地址会被服务端拒绝)'})
    body = api.submit_location(acc['cookie'], acc['ua'], e['activeId'], e['courseId'],
                               e['classId'], _uid_for(acc, e),
                               float(d['lat']), float(d['lon']), d['address'].strip())
    ok, msg = api.classify(body)
    set_entry_state(d['accId'], d['activeId'], '成功' if ok else '失败: ' + msg)
    return jsonify({'ok': ok, 'msg': msg})


@app.post('/api/sign/code')
def sign_code():
    d = request.json or {}
    acc = find_account(d['accId'])
    e = monitor['entries'].get('%s#%s' % (d['accId'], d['activeId']))
    if not (acc and e):
        return jsonify({'ok': False, 'msg': '条目或账号不存在,请先扫描'})
    guard = _already_signed_guard(d, e)
    if guard:
        return guard
    code = d.get('code', '').strip()
    if not code:
        return jsonify({'ok': False, 'msg': '请先填手势串/签到码'})
    res, err = api.check_sign_code(acc['cookie'], acc['ua'], e['activeId'], code)
    if res == 0:
        set_entry_state(d['accId'], d['activeId'], '失败: code 错误')
        return jsonify({'ok': False, 'msg': '校验未通过:手势/签到码错误'})
    if res == -1:
        msg = err or '触发服务端暴力破解封禁,已停止尝试'
        set_entry_state(d['accId'], d['activeId'], '失败: ' + msg)
        return jsonify({'ok': False, 'msg': '服务端拒绝: ' + msg})
    body = api.submit_signcode(acc['cookie'], acc['ua'], e['activeId'], e['courseId'],
                               _uid_for(acc, e), code)
    ok, msg = api.classify(body)
    set_entry_state(d['accId'], d['activeId'], '成功' if ok else '失败: ' + msg)
    return jsonify({'ok': ok, 'msg': msg})


@app.post('/api/decode')
def decode_only():
    """摄像头/图片帧 → 服务端 OpenCV 解码(浏览器只管采集,不依赖其自带识别)"""
    d = request.json or {}
    img = d.get('image') or ''
    if not img:
        return jsonify({'ok': False, 'text': '', 'msg': '无图片'})
    try:
        text = api.decode_qr(base64.b64decode(img.split(',')[-1]))
    except Exception as ex:
        return jsonify({'ok': False, 'text': '', 'msg': '图片解析失败: %s' % ex})
    return jsonify({'ok': bool(text), 'text': text or '',
                    'msg': '' if text else '未识别到二维码'})


@app.post('/api/sign/batch')
def sign_batch():
    """批量二维码:一张图 → 全部(或指定)账号并发提交"""
    d = request.json or {}
    text = d.get('text') or ''
    if d.get('image'):
        img = base64.b64decode(d['image'].split(',')[-1])
        text = api.decode_qr(img) or ''
    p = api.parse_qr_text(text)
    if not p['enc']:
        return jsonify({'ok': False, 'msg': '未能从内容解出有效 enc'})
    ids = d.get('ids') or [a['id'] for a in load_accounts() if not a.get('expired')]
    accs = [a for a in load_accounts() if a['id'] in ids and a.get('cookie')]
    if not accs:
        return jsonify({'ok': False, 'msg': '无可执行账号'})

    def work(a):
        body = api.submit_qr(a['cookie'], a['ua'], p['id'], a['uid'], p['enc'])
        ok, msg = api.classify(body)
        if p['id']:
            set_entry_state(a['id'], p['id'], '成功' if ok else '失败: ' + msg)
        return {'accId': a['id'], 'name': a.get('remark') or a.get('name'),
                'ok': ok, 'msg': msg}

    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(work, accs))
    ok_n = sum(1 for r in results if r['ok'])
    return jsonify({'ok': True, 'activeId': p['id'], 'results': results,
                    'summary': '成功 %d / 失败 %d' % (ok_n, len(results) - ok_n)})


# ------------------------- 启动 -------------------------

def main():
    global ACCESS_TOKEN
    ap = argparse.ArgumentParser(description='学习通签到助手 · 浏览器版(学生端)')
    ap.add_argument('--lan', action='store_true', help='绑定 0.0.0.0 供手机浏览器访问(生成访问令牌)')
    ap.add_argument('--https', action='store_true', help='启用 HTTPS(自签本地 CA)——手机浏览器才能用摄像头')
    ap.add_argument('--port', type=int, default=8787)
    ap.add_argument('--host', default=None)
    args = ap.parse_args()

    host = args.host or ('0.0.0.0' if args.lan else '127.0.0.1')
    if host != '127.0.0.1':
        ACCESS_TOKEN = load_or_create_token()

    scheme, ssl_ctx = 'http', None
    if args.https:
        try:
            cert, key = ensure_certs()
            ssl_ctx = (cert, key)
            scheme = 'https'
        except Exception as ex:
            print('  !! HTTPS 启用失败(证书生成异常,已回落 HTTP): %s' % ex)

    print('学习通签到助手 · 浏览器版(学生端)')
    # '::' 绑定在 Windows 上只收 IPv6(v6only),本机回环要用 [::1]
    print('  本机访问: %s://%s:%d' % (scheme, '[::1]' if ':' in host else '127.0.0.1', args.port))
    if ACCESS_TOKEN:
        print('  手机访问(同一网络内,任选其一):')
        for ip in _local_ips():
            if ':' in ip:
                print('    %s://[%s]:%d/?k=%s' % (scheme, ip, args.port, ACCESS_TOKEN))
            else:
                print('    %s://%s:%d/?k=%s' % (scheme, ip, args.port, ACCESS_TOKEN))
        if ssl_ctx:
            print('  HTTPS 证书:本地 CA 自签(手机首次需信任,二选一):')
            print('    A. 装 CA(推荐,一次管十年):把 %s 装进手机「设置→安全→加密与凭据→安装证书→CA 证书」' % os.path.join(CERT_DIR, 'ca.crt'))
            print('       也可手机浏览器开 %s://<IP>:%d/ca.crt 下载后再装。' % (scheme, args.port))
            print('    B. 不装也行:浏览器提示"不是私密连接"→高级→继续前往(部分浏览器仍需装 CA 才给摄像头)。')
        else:
            print('  !! 局域网明文 HTTP:手机浏览器将禁用摄像头;需要扫码请加 --https。')
        print('  !! 令牌为唯一门禁,勿外传。')
    app.run(host=host, port=args.port, threaded=True, debug=False, ssl_context=ssl_ctx)


if __name__ == '__main__':
    main()
