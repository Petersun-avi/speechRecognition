#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Date    : 2018-12-02 19:04:55
import openBrower
import getAPI
import wave
import time
from pyaudio import PyAudio, paInt16
framerate = 16000  # 采样率
num_samples = 2000  # 采样点
channels = 1  # 声道
sampwidth = 2  # 采样宽度2bytes
FILEPATH = 'speech.wav'

base_url = "https://openapi.baidu.com/oauth/2.0/token?grant_type=client_credentials&client_id=%s&client_secret=%s"
APIKey = "NiFLjUj7ko05xGPtNWzHrzlo"
SecretKey = "CpPUpyviy9jKS2bkG0EQIqweLXPZ8XGp"
HOST = base_url % (APIKey, SecretKey)
flag = 'y'
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


def get_audio(file):
    with open(file, 'rb') as f:
        data = f.read()
    return data

while flag.lower() == 'y':
    print('请输入数字选择语言：')
    devpid = input('1536：普通话(简单英文),1537:普通话(有标点),1737:英语,1637:粤语,1837:四川话\n')
    my_record()
    TOKEN = getAPI.getToken(HOST)
    speech = get_audio(FILEPATH)
    result = getAPI.speech2text(speech, TOKEN, int(devpid))
    print(result)
    if type(result) == str:
        openBrower.openbrowser(result.strip('，'))
    flag = input('Continue?(y/n):')
