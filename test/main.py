# -*- coding:utf-8 -*-
import websocket
import datetime
from urllib.parse import urlencode
import ssl
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime
import _thread as thread
import re
import json
from urllib import request
import hmac
import hashlib
import random
import os
import time
import ast
import base64
import requests

base_url = "https://openapi.baidu.com/oauth/2.0/token?grant_type=client_credentials&client_id=%s&client_secret=%s"
APIKey = "NiFLjUj7ko05xGPtNWzHrzlo"
SecretKey = "CpPUpyviy9jKS2bkG0EQIqweLXPZ8XGp"
HOST = base_url % (APIKey, SecretKey)

FILEPATH = 'test.wav'
secret_key = 'C7lNimZ5LK3VfYBXcPvA8pFOHxMVMwFP'
secretid = 'AKIDqSoujHXYIlxtXu0pNefPs4zd18xVmmVx'
appid = 1306225777

engine_model_type = '16k_0'
res_type = 0
result_text_format = 0
voice_format = 1
cutlength = 20000
template_name = ""


def get_audio(file):
    with open(file, 'rb') as f:
        data = f.read()
    return data


def getToken(host):
    res = requests.post(host)
    return res.json()['access_token']


def speech2text(speech_data, token, dev_pid=1537):
    FORMAT = 'wav'
    RATE = '16000'
    CHANNEL = 1
    CUPID = '*******'
    SPEECH = base64.b64encode(speech_data).decode('utf-8')

    data = {
        'format': FORMAT,
        'rate': RATE,
        'channel': CHANNEL,
        'cuid': CUPID,
        'len': len(speech_data),
        'speech': SPEECH,
        'token': token,
        'dev_pid': dev_pid
    }
    url = 'https://vop.baidu.com/server_api'
    headers = {'Content-Type': 'application/json'}
    # r=requests.post(url,data=json.dumps(data),headers=headers)
    r = requests.post(url, json=data, headers=headers)
    Result = r.json()
    if 'result' in Result:
        return Result['result'][0]
    else:
        return Result


def formatSignString(param):
    signstr = "POSTaai.qcloud.com/asr/v1/"
    for t in param:
        if 'appid' in t:
            signstr += str(t[1])
            break
    signstr += "?"
    for x in param:
        tmp = x
        if 'appid' in x:
            continue
        for t in tmp:
            signstr += str(t)
            signstr += "="
        signstr = signstr[:-1]
        signstr += "&"
    signstr = signstr[:-1]
    # print 'signstr',signstr
    return signstr


def sign(signstr, secret_key):
    # python3做二进制转换
    bytes_signstr = bytes(signstr, 'utf-8')
    bytes_secret_key = bytes(secret_key, 'utf-8')
    # bytes_secret_key = bytes(secret_key, 'latin-1')

    hmacstr = hmac.new(bytes_secret_key, bytes_signstr, hashlib.sha1).digest()
    s = base64.b64encode(hmacstr)
    # print 'sign: ',s
    return s


def randstr(n):
    seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sa = []
    for i in range(n):
        sa.append(random.choice(seed))
    salt = ''.join(sa)
    # print salt
    return salt


def sendVoice(secret_key, secretid, appid, engine_model_type, res_type, result_text_format, voice_format, filepath,
              cutlength, template_name="", filter_punc=2):
    if len(str(secret_key)) == 0:
        print('secretKey can not empty')
        return
    if len(str(secretid)) == 0:
        print('secretid can not empty')
        return
    if len(str(appid)) == 0:
        print('appid can not empty')
        return
    if len(str(engine_model_type)) == 0 or (
            str(engine_model_type) != '8k_0' and str(engine_model_type) != '16k_0' and str(
        engine_model_type) != '16k_en'):
        print('engine_model_type is not right')
        return
    if len(str(res_type)) == 0 or (str(res_type) != '0' and str(res_type) != '1'):
        print('res_type is not right')
        return
    if len(str(result_text_format)) == 0 or (str(result_text_format) != '0' and str(result_text_format) != '1' and str(
            result_text_format) != '2' and str(result_text_format) != '3'):
        print('result_text_format is not right')
        return
    if len(str(voice_format)) == 0 or (
            str(voice_format) != '1' and str(voice_format) != '4' and str(voice_format) != '6'):
        print('voice_format is not right')
        return
    if len(str(filepath)) == 0:
        print('filepath can not empty')
        return
    if len(str(cutlength)) == 0 or str(cutlength).isdigit() == False or cutlength > 200000:
        print('cutlength can not empty')
        return
    # secret_key = "oaYWFO70LGDmcpfwo8uF1IInayysGtgZ"
    query_arr = dict()
    query_arr['appid'] = appid
    query_arr['projectid'] = 1013976
    if len(template_name) > 0:
        query_arr['template_name'] = template_name
    query_arr['sub_service_type'] = 1
    query_arr['engine_model_type'] = engine_model_type
    query_arr['res_type'] = res_type
    query_arr['result_text_format'] = result_text_format
    query_arr['voice_id'] = randstr(16)
    query_arr['timeout'] = 100
    query_arr['source'] = 0
    query_arr['secretid'] = secretid
    query_arr['timestamp'] = str(int(time.time()))
    query_arr['expired'] = int(time.time()) + 24 * 60 * 60
    query_arr['nonce'] = query_arr['timestamp'][0:4]
    query_arr['voice_format'] = voice_format
    file_object = open(filepath, 'rb')
    file_object.seek(0, os.SEEK_END)
    datalen = file_object.tell()
    file_object.seek(0, os.SEEK_SET)
    seq = 0
    while (datalen > 0):
        end = 0
        if (datalen < cutlength):
            end = 1
        query_arr['end'] = end
        query_arr['seq'] = seq
        query = sorted(query_arr.items(), key=lambda d: d[0])
        signstr = formatSignString(query)
        autho = sign(signstr, secret_key)

        if (datalen < cutlength):
            content = file_object.read(datalen)
        else:
            content = file_object.read(cutlength)
        seq = seq + 1
        datalen = datalen - cutlength
        headers = {}
        headers['Authorization'] = autho
        headers['Content-Length'] = len(content)
        requrl = "http://"
        requrl += signstr[4::]

        # python3
        req = request.Request(requrl, data=content, headers=headers)

        res_data = request.urlopen(req)
        # time.sleep(0.3)
        res = res_data.read().decode('utf-8')
        res_dict = ast.literal_eval(res)
        res_dict['text'] = re.sub(r'[^\w\s]', '', res_dict['text'])
    if res_dict['text'] != "":
        print(res_dict['text'])

    file_object.close()
    return res


def get_result(file_path):
    res = sendVoice(secret_key=secret_key, secretid=secretid, appid=appid, engine_model_type=engine_model_type,
                    res_type=res_type, result_text_format=result_text_format, voice_format=voice_format,
                    cutlength=cutlength, filepath=file_path, filter_punc=1)
    res_dict = json.loads(res)
    data = res_dict.get('text')
    return data


STATUS_FIRST_FRAME = 0  # 第一帧的标识
STATUS_CONTINUE_FRAME = 1  # 中间帧标识
STATUS_LAST_FRAME = 2  # 最后一帧的标识


class Ws_Param(object):
    # 初始化
    def __init__(self, APPID, APIKey, APISecret, AudioFile):
        self.APPID = APPID
        self.APIKey = APIKey
        self.APISecret = APISecret
        self.AudioFile = AudioFile

        # 公共参数(common)
        self.CommonArgs = {"app_id": self.APPID}
        # 业务参数(business)，更多个性化参数可在官网查看
        self.BusinessArgs = {"domain": "iat", "language": "zh_cn", "accent": "mandarin", "vinfo": 1, "vad_eos": 10000}

    # 生成url
    def create_url(self):
        url = 'wss://ws-api.xfyun.cn/v2/iat'
        # 生成RFC1123格式的时间戳
        now = datetime.now()
        date = format_date_time(mktime(now.timetuple()))

        # 拼接字符串
        signature_origin = "host: " + "ws-api.xfyun.cn" + "\n"
        signature_origin += "date: " + date + "\n"
        signature_origin += "GET " + "/v2/iat " + "HTTP/1.1"
        # 进行hmac-sha256进行加密
        signature_sha = hmac.new(self.APISecret.encode('utf-8'), signature_origin.encode('utf-8'),
                                 digestmod=hashlib.sha256).digest()
        signature_sha = base64.b64encode(signature_sha).decode(encoding='utf-8')

        authorization_origin = "api_key=\"%s\", algorithm=\"%s\", headers=\"%s\", signature=\"%s\"" % (
            self.APIKey, "hmac-sha256", "host date request-line", signature_sha)
        authorization = base64.b64encode(authorization_origin.encode('utf-8')).decode(encoding='utf-8')
        # 将请求的鉴权参数组合为字典
        v = {
            "authorization": authorization,
            "date": date,
            "host": "ws-api.xfyun.cn"
        }
        # 拼接鉴权参数，生成url
        url = url + '?' + urlencode(v)
        # print("date: ",date)
        # print("v: ",v)
        # 此处打印出建立连接时候的url,参考本demo的时候可取消上方打印的注释，比对相同参数时生成的url与自己代码生成的url是否一致
        # print('websocket url :', url)
        return url


# 收到websocket消息的处理
def on_message(ws, message):
    try:
        code = json.loads(message)["code"]
        sid = json.loads(message)["sid"]
        if code != 0:
            errMsg = json.loads(message)["message"]
            print("sid:%s call error:%s code is:%s" % (sid, errMsg, code))

        else:
            data = json.loads(message)["data"]["result"]["ws"]
            # print(json.loads(message))
            result = ""
            for i in data:
                for w in i["cw"]:
                    w["w"] = re.sub(r'[^\w\s]', '', w["w"])
                    if w["w"] != "":
                        result += w["w"]

            print(result)
            with open("word.txt", "a") as file:
                file.writelines(result + '\n')


    except Exception as e:
        print("receive msg,but parse exception:", e)


# 收到websocket错误的处理
def on_error(ws, error):
    print("发生错误！t", '\t', error)


# 收到websocket关闭的处理
def on_close(ws):
    pass


# 收到websocket连接建立的处理
def on_open(ws):
    def run(*args):
        frameSize = 8000  # 每一帧的音频大小
        intervel = 0.04  # 发送音频间隔(单位:s)
        status = STATUS_FIRST_FRAME  # 音频的状态信息，标识音频是第一帧，还是中间帧、最后一帧

        with open(wsParam.AudioFile, "rb") as fp:
            while True:
                buf = fp.read(frameSize)
                # 文件结束
                if not buf:
                    status = STATUS_LAST_FRAME
                # 第一帧处理
                # 发送第一帧音频，带business 参数
                # appid 必须带上，只需第一帧发送
                if status == STATUS_FIRST_FRAME:

                    d = {"common": wsParam.CommonArgs,
                         "business": wsParam.BusinessArgs,
                         "data": {"status": 0, "format": "audio/L16;rate=16000",
                                  "audio": str(base64.b64encode(buf), 'utf-8'),
                                  "encoding": "raw"}}
                    d = json.dumps(d)
                    ws.send(d)
                    status = STATUS_CONTINUE_FRAME
                # 中间帧处理
                elif status == STATUS_CONTINUE_FRAME:
                    d = {"data": {"status": 1, "format": "audio/L16;rate=16000",
                                  "audio": str(base64.b64encode(buf), 'utf-8'),
                                  "encoding": "raw"}}
                    ws.send(json.dumps(d))
                # 最后一帧处理
                elif status == STATUS_LAST_FRAME:
                    d = {"data": {"status": 2, "format": "audio/L16;rate=16000",
                                  "audio": str(base64.b64encode(buf), 'utf-8'),
                                  "encoding": "raw"}}
                    ws.send(json.dumps(d))
                    time.sleep(1)
                    break
                # 模拟音频采样间隔
                time.sleep(intervel)
        ws.close()

    thread.start_new_thread(run, ())


if __name__ == '__main__':
    time1 = datetime.now()
    print("百度:")
    TOKEN = getToken(HOST)
    speech = get_audio(FILEPATH)
    result = speech2text(speech, TOKEN, 1536)
    print(result)
    time2 = datetime.now()
    print(time2 - time1)
    print("----------")
    print("腾讯:")
    time1 = datetime.now()
    get_result(FILEPATH)
    time2 = datetime.now()
    print(time2 - time1)
    print("----------")
    print("讯飞：")
    time1 = datetime.now()
    wsParam = Ws_Param(APPID='2028efc3', APISecret='OGQ4MjgxYzFiM2U5MzQwODcxYjhhNGYz',
                       APIKey='2fd957c9ea98927ea750d143b0fac962',
                       AudioFile=FILEPATH)
    websocket.enableTrace(False)
    wsUrl = wsParam.create_url()
    ws = websocket.WebSocketApp(wsUrl, on_message=on_message, on_error=on_error, on_close=on_close)
    ws.on_open = on_open
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
    time2 = datetime.now()
    print(time2 - time1)
    print("录音结束")

