import random


def random_impersonate():
    impersonate = random.choice(['chrome124', 'chrome123', 'chrome120', 'edge99', 'edge101', 'safari17_0'])
    if impersonate == 'chrome124':
        return impersonate, random_ua('chrome', '124')
    elif impersonate == 'chrome123':
        return impersonate, random_ua('chrome', '123')
    elif impersonate == 'chrome120':
        return impersonate, random_ua('chrome', '120')
    elif impersonate == 'edge99':
        return impersonate, random_ua('edge', '99')
    elif impersonate == 'edge101':
        return impersonate, random_ua('edge', '101')
    elif impersonate == 'safari17_0':
        return impersonate, random_ua('safari', '17')
    else:
        return None, None


def random_ua(browser, major_version):
    # 定义操作系统及其可能的版本
    os_options = {
        'Windows': ['Windows NT 10.0; Win64; x64', 'Windows NT 11.0; Win64; x64'],
        'macOS': ['Macintosh; Intel Mac OS X 10_15_7', 'Macintosh; Intel Mac OS X 10_15_6',
                  'Macintosh; Intel Mac OS X 10_15_5', 'Macintosh; Intel Mac OS X 10_15_4',
                  'Macintosh; Intel Mac OS X 10_15_3', 'Macintosh; Intel Mac OS X 10_15_2',
                  'Macintosh; Intel Mac OS X 10_15_1'
                  ],
        'Linux': ['X11; Linux x86_64', 'X11; Ubuntu; Linux x86_64']
    }

    # 选择一个随机的操作系统和版本
    if browser.lower() == 'safari':
        os_platform = 'macOS'
    else:
        os_platform = random.choice(list(os_options.keys()))
    os_version = random.choice(os_options[os_platform])

    sec_ch_ua_platform = f'"{os_platform}"'

    # 随机小版本和修订号
    minor_version = random.randint(5000, 5500)
    build_version = random.randint(0, 200)

    # 根据浏览器生成用户代理
    if browser.lower() == 'chrome':
        template = f"Mozilla/5.0 ({os_version}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major_version}.0.{minor_version}.{build_version} Safari/537.36"
        sec_ch_ua = f'"Google Chrome";v="{major_version}", "Chromium";v="{major_version}", "Not.A/Brand";v="24"'
        ua_headers = {
            "Sec-ch-ua": sec_ch_ua,
            "User-Agent": template,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-ch-ua-platform": sec_ch_ua_platform
        }
    elif browser.lower() == 'edge':
        template = f"Mozilla/5.0 ({os_version}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major_version}.0.{minor_version}.{build_version} Safari/537.36 Edg/{major_version}.0.{minor_version}.{build_version}"
        sec_ch_ua = f'"Not/A)Brand";v="8", "Chromium";v="{major_version}", "Microsoft Edge";v="{major_version}"'
        ua_headers = {
            "Sec-ch-ua": sec_ch_ua,
            "User-Agent": template,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-ch-ua-platform": sec_ch_ua_platform
        }
    elif browser.lower() == 'safari':
        webkit_version = random.randint(600, 605)
        template = f"Mozilla/5.0 ({os_version}) AppleWebKit/{webkit_version}.1.15 (KHTML, like Gecko) Version/{major_version}.0 Safari/{webkit_version}.1.15"
        ua_headers = {
            "User-Agent": template,
        }
    else:
        return None
    return ua_headers


# 示例使用
# browser = 'safari'
# major_version = '17'
# user_agent = random_ua(browser, major_version)
print("Generated User Agent:", random_impersonate())
