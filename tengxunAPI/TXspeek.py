import json

# python3导入
from urllib import request

import hmac
import hashlib
import base64
import random
import os
import wave
import time
import ast
from pyaudio import PyAudio, paInt16

framerate = 16000  # 采样率
num_samples = 2000  # 采样点
channels = 1  # 声道
sampwidth = 2  # 采样宽度2bytes
FILEPATH = 'speech.wav'
flag = 'y'

secret_key = 'C7lNimZ5LK3VfYBXcPvA8pFOHxMVMwFP'
secretid = 'AKIDqSoujHXYIlxtXu0pNefPs4zd18xVmmVx'
appid = 1306225777

engine_model_type = '16k_0'
res_type = 0
result_text_format = 0
voice_format = 1
cutlength = 20000
template_name = ""


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
              cutlength, template_name=""):
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
        if res_dict["text"] != "":
            res_dict["text"] = res_dict["text"][:-1]
            print(res_dict["text"])

    file_object.close()

    return res


def get_result(file_path):
    res = sendVoice(secret_key=secret_key, secretid=secretid, appid=appid, engine_model_type=engine_model_type,
                    res_type=res_type, result_text_format=result_text_format, voice_format=voice_format,
                    cutlength=cutlength, filepath=file_path)
    res_dict = json.loads(res)
    data = res_dict.get('text')
    return data


def save_wave_file(filepath, data):
    wf = wave.open(filepath, 'wb')
    wf.setnchannels(channels)
    wf.setsampwidth(sampwidth)
    wf.setframerate(framerate)
    wf.writeframes(b''.join(data))
    wf.close()


def my_record():
    pa = PyAudio()
    stream = pa.open(format=paInt16, channels=channels,
                     rate=framerate, input=True, frames_per_buffer=num_samples)
    my_buf = []
    # count = 0
    t = time.time()
    print('正在录音...')

    while time.time() < t + 4:  # 秒
        string_audio_data = stream.read(num_samples)
        my_buf.append(string_audio_data)
    print('录音结束.')
    save_wave_file(FILEPATH, my_buf)
    stream.close()


if __name__ == '__main__':
    while flag.lower() == 'y':
        my_record()
        get_result(FILEPATH)
        flag = input('Continue?(y/n):')
