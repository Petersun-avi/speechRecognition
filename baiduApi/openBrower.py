import webbrowser
def openbrowser(text):
    maps = {
        '百度': ['百度', 'baidu'],
        '腾讯': ['腾讯', 'tengxun'],
        '网易': ['网易', 'wangyi']
    }
    if text in maps['百度']:
        webbrowser.open_new_tab('https://www.baidu.com')
    elif text in maps['腾讯']:
        webbrowser.open_new_tab('https://www.qq.com')
    elif text in maps['网易']:
        webbrowser.open_new_tab('https://www.163.com/')
    else:
        webbrowser.open_new_tab('https://www.baidu.com/s?wd=%s' % text)