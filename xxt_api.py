# -*- coding: utf-8 -*-
"""学习通学生端协议(浏览器版) —— 参数面逐条对齐 chaoxing-student 沙盘实测。

白名单(与手机 App 同纪律,教师端接口禁止进入本文件):
  发短信/登录/档案  passport2 / sso
  活动列表          ketang-zhizhen /education/student/activelist
  签到页            mobilelearn /newsign/preSign
  签到提交          mobilelearn /pptSign/stuSignajax(普通/二维码/位置/手势/签到码)
  码预校验          mobilelearn /widget/sign/pcStuSignController/checkSignCode
"""
import hashlib
import random
import re
import time

import requests

CAPTCHA_SALT = "jsDyctOCnay7uotq"          # 逆向自学生端 dex,真机抓包验证
MOBILELEARN = "https://mobilelearn.chaoxing.com"
KETANG = "https://ketang-zhizhen.chaoxing.com"

# 设备指纹池(每账号绑定一套,避免全部账号同指纹)
_DEVICES = [
    ("M2012K10C", "13", "TKQ1.221114.001"), ("2211133C", "13", "TKQ1.221114.001"),
    ("V2309A", "14", "UP1A.231005"), ("PHY110", "14", "UKQ1.230924"),
    ("ALN-AL00", "12", "HUAWEIALN-AL00"), ("SM-S9280", "14", "UP1A.231005"),
    ("23127PN0CC", "14", "UKQ1.230804"), ("PJD110", "14", "UKQ1.230924"),
]


def gen_dalvik_ua():
    model, android, build = random.choice(_DEVICES)
    app_build = "109%d_%d" % (random.randint(80, 89), random.randint(320, 369))
    return ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s) (device:%s) "
            "Language/zh_CN_#Hans com.chaoxing.mobile/ChaoXingStudy_3_7.0.4_android_phone_%s"
            % (android, model, build, model, app_build))


def md5(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def _headers(cookie=None, ua=None, extra=None):
    h = {'Accept-Language': 'zh_CN_#Hans'}
    if cookie:
        h['Cookie'] = cookie
    if ua:
        h['User-Agent'] = ua
    if extra:
        h.update(extra)
    return h


# ------------------------- 通行证 -------------------------

def send_captcha(phone, ua=None, timeout=20):
    """POST /api/sendcaptcha —— enc = md5(手机号 + 盐 + 毫秒时间戳)"""
    ts = int(time.time() * 1000)
    r = requests.post('https://passport2-api.chaoxing.com/api/sendcaptcha',
                      data={'to': phone, 'countrycode': '86', 'time': str(ts),
                            'enc': md5(phone + CAPTCHA_SALT + str(ts))},
                      headers=_headers(ua=ua or gen_dalvik_ua()), timeout=timeout)
    try:
        j = r.json()
    except Exception:
        return False, '响应异常(HTTP %s)' % r.status_code
    ok = j.get('status') is True
    return ok, (j.get('mes') or j.get('error') or ('验证码已发送' if ok else '发送失败'))


def login(uname, code, is_sms=True, ua=None, timeout=25):
    """POST /v11/loginregister?cx_xxt_passport=json —— 返回 (ok, msg, cookie)"""
    ua = ua or gen_dalvik_ua()
    r = requests.post('https://passport2-api.chaoxing.com/v11/loginregister?cx_xxt_passport=json',
                      data={'uname': uname.strip(), 'code': code.strip(),
                            'loginType': '2' if is_sms else '1',
                            'countrycode': '86', 'roleSelect': 'true'},
                      headers=_headers(ua=ua), timeout=timeout)
    try:
        j = r.json()
    except Exception:
        return False, '响应异常(HTTP %s)' % r.status_code, ''
    ok = j.get('status') is True or j.get('result') == 1
    if not ok:
        return False, (j.get('mes') or j.get('msg2') or j.get('error') or '账号或验证码/密码错误'), ''
    cookie = '; '.join('%s=%s' % (c.name, c.value) for c in r.cookies)
    return True, '登录成功', cookie


def sso_info(cookie, ua=None, timeout=20):
    """POST sso userLogin4Uname —— 档案/有效性"""
    try:
        r = requests.post('https://sso.chaoxing.com/apis/login/userLogin4Uname.do?_from=passport',
                          headers=_headers(cookie=cookie, ua=ua or gen_dalvik_ua()), timeout=timeout)
        j = r.json()
        m = j.get('msg') or {}
        valid = j.get('result') == 1 or bool(m.get('uid') or m.get('name'))
        return {'valid': valid, 'uid': str(m.get('uid') or ''), 'name': m.get('name') or '',
                'nick': m.get('nick') or '', 'school': m.get('schoolname') or '',
                'uname': m.get('uname') or '', 'phone': m.get('phone') or ''}
    except Exception:
        return {'valid': False, 'uid': '', 'name': '', 'nick': '', 'school': '', 'uname': '', 'phone': ''}


# ------------------------- 学生端 -------------------------

def active_list(cookie, ua, status_set=1, timeout=25):
    """POST educaion/student/activelist —— 返回 (ok, msg, course_json, entries)"""
    try:
        r = requests.post(KETANG + '/education/student/activelist?DB_STRATEGY=DEFAULT',
                          data={'classIds': '', 'startTimeSet': '', 'endTimeSet': '',
                                'statusSet': status_set, 'keyWord': '', 'reload': 0, 'devices': 1,
                                'includeWork': 1, 'includeExam': 1, 'includeRead': 1},
                          headers=_headers(cookie=cookie, ua=ua), timeout=timeout)
        j = r.json()
        data = j.get('data') or {}
        cj = data.get('courseJson') or {}
        entries = []
        for e in (data.get('array') or []):
            if str(e.get('activeType')) != '2':
                continue                      # 只看签到类
            entries.append({
                'activeId': str(e.get('id')), 'classId': str(e.get('classId') or ''),
                'courseId': str(cj.get(str(e.get('classId'))) or ''),
                'courseName': e.get('courseName') or '', 'otherId': str(e.get('otherId')),
                'title': e.get('nameOne') or '', 'remain': e.get('nameFour') or '',
                'startTime': e.get('startTime') or 0, 'endTime': e.get('endTime') or 0,
            })
        return True, 'ok', cj, entries
    except Exception as ex:
        return False, str(ex), {}, []


def presign_page(cookie, ua, uid, course_id, class_id, active_id, timeout=20):
    """GET newsign/preSign —— 页面态:渲染 uid + 已签标记(只认 zsign_success)"""
    url = (MOBILELEARN + '/newsign/preSign?courseId=%s&classId=%s&activePrimaryId=%s'
           '&general=1&sys=1&ls=1&appType=15&uid=%s&isTeacherViewOpen=0'
           % (course_id, class_id, active_id, uid))
    try:
        r = requests.get(url, headers=_headers(cookie=cookie, ua=ua), timeout=timeout)
        html = r.text
        m = re.search(r'id="uid"[^>]*value="(\d+)"', html) or re.search(r"uid\s*=\s*'?(\d{5,})'?", html)
        return {'ok': True, 'uid': m.group(1) if m else str(uid), 'signed': 'zsign_success' in html}
    except Exception as ex:
        return {'ok': False, 'uid': str(uid), 'signed': False, 'error': str(ex)}


def _stu_sign_get(cookie, ua, query, timeout=15):
    try:
        r = requests.get(MOBILELEARN + '/pptSign/stuSignajax?' + query,
                         headers=_headers(cookie=cookie, ua=ua), timeout=timeout)
        return r.text
    except Exception as ex:
        return 'ERROR:%s' % ex


def submit_normal(cookie, ua, active_id, course_id, uid):
    return _stu_sign_get(cookie, ua,
                         'activeId=%s&courseId=%s&uid=%s&clientip=&useragent='
                         '&latitude=-1&longitude=-1&appType=15&fid=0&name=&deviceCode='
                         % (active_id, course_id, uid))


def submit_qr(cookie, ua, active_id, uid, enc):
    return _stu_sign_get(cookie, ua,
                         'enc=%s&name=&activeId=%s&uid=%s&clientip=&location='
                         '&latitude=-1&longitude=-1&appType=15&fid=0&deviceCode='
                         '&vpProbability=&vpStrategy=' % (enc, active_id, uid))


def submit_signcode(cookie, ua, active_id, course_id, uid, sign_code):
    return _stu_sign_get(cookie, ua,
                         'activeId=%s&courseId=%s&uid=%s&clientip=&latitude=-1&longitude=-1'
                         '&appType=15&fid=0&name=&signCode=%s&deviceCode=&location='
                         % (active_id, course_id, uid, sign_code))


def submit_location(cookie, ua, active_id, course_id, class_id, uid, lat, lon, address):
    url = (MOBILELEARN + '/newsign/preSign?courseId=%s&classId=%s&activePrimaryId=%s'
           % (course_id, class_id, active_id))
    try:
        r = requests.post(MOBILELEARN + '/pptSign/stuSignajax',
                          data={'name': '', 'address': address, 'activeId': active_id,
                                'courseId': course_id, 'uid': uid, 'clientip': '',
                                'latitude': str(lat), 'longitude': str(lon), 'fid': '0',
                                'appType': '15', 'ifTiJiao': '1', 'validate': '',
                                'deviceCode': '', 'vpProbability': '', 'vpStrategy': '',
                                'currentFaceId': '', 'ifCFP': '0', 'faceEnc': '', 'faceCode': '',
                                'locationResult': ''},
                          headers=_headers(cookie=cookie, ua=ua, extra={'Referer': url}),
                          timeout=15)
        return r.text
    except Exception as ex:
        return 'ERROR:%s' % ex


def check_sign_code(cookie, ua, active_id, sign_code, timeout=15):
    """手势/签到码预校验:1=对 / 0=错 / -1=服务端封禁 / -2=接口不可用"""
    try:
        r = requests.get(MOBILELEARN + '/widget/sign/pcStuSignController/checkSignCode',
                         params={'activeId': active_id, 'signCode': sign_code},
                         headers=_headers(cookie=cookie, ua=ua), timeout=timeout)
        j = r.json()
        return j.get('result', -2), j.get('errorMsg') or ''
    except Exception as ex:
        return -2, str(ex)


def classify(body):
    """提交响应判定(contract:success/success2;validate_/checkFace_ 如实上报)"""
    if not body:
        return False, '无响应内容'
    if body.startswith('ERROR:'):
        return False, '请求异常: ' + body[6:]
    t = body.strip()
    if t in ('success', 'success2'):
        return True, '签到成功!'
    if t.startswith('validate_'):
        return False, '被要求图形验证码,请在官方 App 内完成'
    if t.startswith('checkFace_'):
        return False, '被要求人脸识别,请在官方 App 内完成'
    if 'zsign_success' in body:
        return True, '签到成功!'
    if '您已签到过了' in body or '已签到' in body:
        return True, '此前已签到过'
    if '老师不能参与签到' in body:
        return False, '老师不能参与签到(该课内当前身份为教师)'
    if '此次签到未开始' in body:
        return False, '签到未开始'
    if '重新扫描' in body:
        return False, '二维码已失效,请重新获取'
    if '截止时间' in body or '下次早点来' in body:
        return False, '签到已截止'
    if '指定范围' in body or '不在签到范围' in body:
        return False, '不在签到范围(GPS 距离不满足)'
    if '未加入该班级' in body or '未找到活动' in body:
        return False, '未加入此班级课程'
    return False, '签到未通过: %s' % re.sub(r'<[^>]+>', ' ', body)[:80].strip()


# ------------------------- 二维码图像解码(OpenCV) -------------------------

def decode_qr(image_bytes):
    """截图/相册图片 → 二维码文本;失败返回 None。

    重试阶梯(实测:小图/裁太紧的图直接识别会失败):
      原图 → 放大 → 补静区 → 缩到 ~1400 再试
    """
    try:
        import cv2
        import numpy as np
        img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            return None
        det = cv2.QRCodeDetector()

        def try_decode(im):
            d, _, _ = det.detectAndDecode(im)
            return d or None

        h, w = img.shape[:2]
        cands = [img]
        if max(h, w) < 800:                       # 小图:放到 ~800 再识别
            f = 800.0 / max(h, w)
            interp = cv2.INTER_NEAREST if max(h, w) < 200 else cv2.INTER_LINEAR
            cands.append(cv2.resize(img, None, fx=f, fy=f, interpolation=interp))
        if max(h, w) > 1400:                      # 超大图:降到 1400
            f = 1400.0 / max(h, w)
            cands.append(cv2.resize(img, None, fx=f, fy=f, interpolation=cv2.INTER_AREA))
        for c in list(cands):                     # 每个候选再补一圈静区
            h2, w2 = c.shape[:2]
            pad = max(16, int(max(h2, w2) * 0.08))
            cands.append(cv2.copyMakeBorder(c, pad, pad, pad, pad,
                                            cv2.BORDER_CONSTANT, value=(255, 255, 255)))
        for c in cands:
            d = try_decode(c)
            if d:
                return d
        return None
    except Exception:
        return None


def parse_qr_text(text):
    """二维码文本 → {id, c, enc}(兼容 URL / SIGNIN: / 裸串)"""
    from urllib.parse import parse_qs, unquote

    def qs(s):
        s = s.split('?', 1)[1] if '?' in s else s
        d = parse_qs(s, keep_blank_values=True)
        return {k: unquote(v[0]) for k, v in d.items()}

    text = (text or '').strip()
    if 'http' in text:
        q = qs(text)
        return {'id': q.get('id') or q.get('activePrimaryId') or q.get('aid') or '',
                'c': q.get('c') or q.get('Code') or '', 'enc': q.get('enc') or ''}
    if 'SIGNIN:' in text:
        q = qs(text.replace('SIGNIN:', ''))
        return {'id': q.get('aid') or q.get('id') or '', 'c': q.get('Code') or q.get('c') or '',
                'enc': q.get('enc') or ''}
    m = re.search(r'(?:id|aid|activePrimaryId)=(\d+)', text)
    e = re.search(r'enc=([A-Fa-f0-9]+)', text)
    return {'id': m.group(1) if m else '', 'c': '', 'enc': e.group(1) if e else ''}
