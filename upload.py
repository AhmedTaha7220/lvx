import json
import hmac
import hashlib
import time
import urllib.parse
import uuid
import json
from datetime import datetime
import requests


# RFC3986 编码
def rfc3986_encode(str_value):
    return urllib.parse.quote(str_value, safe='~').replace('~', '%7E').replace('%20', '+')


# 生成阿里云签名
def ali_sign(access_key_id,access_key_secret, url, method, headers, body):
    """
    生成阿里云请求签名。

    参数:
    - url: 请求的URL。
    - method: 请求方法，如GET、POST等。
    - headers: 请求头，字典格式。
    - body: 请求体，通常为字典格式。

    返回:
    - 签名字符串。
    """
    # Step 1: 规范化请求
    url_object = urllib.parse.urlparse(url)

    canonical_uri = '/'.join([rfc3986_encode(part) for part in url_object.path.split('/')])
    if not canonical_uri.startswith('/'):
        canonical_uri = '/' + canonical_uri
    query_params = sorted([
        f"{rfc3986_encode(key)}={rfc3986_encode(value)}" if value else rfc3986_encode(key)
        for key, value in urllib.parse.parse_qsl(url_object.query)
    ])
    canonical_query_string = '&'.join(query_params)

    headers1 = {key.lower(): value for key, value in headers.items()}

    canonical_headers = ''.join(
        f"{key.lower()}:{value.strip()}\n"
        for key, value in sorted(headers1.items())
        if key.lower().startswith('x-acs-') or key.lower() in ['host', 'content-type']
    )

    signed_headers = ';'.join(
        key.lower()
        for key in sorted(headers1.keys())
        if key.lower().startswith('x-acs-') or key.lower() in ['host', 'content-type']
    )

    # json_body = json.dumps(body, separators=(',', ':'))
    hashed_request_payload = hashlib.sha256(json.dumps(body).encode()).hexdigest()

    canonical_request = '\n'.join([
        method,
        canonical_uri,
        canonical_query_string,
        canonical_headers,
        signed_headers,
        hashed_request_payload
    ])

    # Step 2: 构造待签名字符串
    signature_algorithm = 'ACS3-HMAC-SHA256'
    hashed_canonical_request = hashlib.sha256(canonical_request.encode()).hexdigest()
    string_to_sign = '\n'.join([signature_algorithm, hashed_canonical_request])

    # Step 3: 计算签名
    signature = hmac.new(
        access_key_secret.encode(),
        string_to_sign.encode(),
        hashlib.sha256
    ).hexdigest()

    # Step 4: 返回签名
    return f"{signature_algorithm} Credential={access_key_id},SignedHeaders={signed_headers},Signature={signature}"


def read_from_file_path(path: str) -> bytes:
    with open(path, 'rb') as file:
        return file.read()


def generate_client_token():
    # 生成一个UUID作为ClientToken，确保不同请求间该参数值唯一。
    # UUID是128位的数字，通常以32个十六进制字符表示，中间用连字符分隔。
    # 这里使用uuid4()函数生成一个随机的UUID。
    return str(uuid.uuid4())


def get_create_time():
    # 获取当前时间并转换为Unix时间戳（自1970年1月1日以来的秒数）。
    # 使用time模块中的time()函数来得到当前时间。
    return int(time.time())


# 发送消息并处理响应
def upload_message(access_key_id, access_key_secret, workspace_id, ur, file_name):
    host = 'farui.cn-beijing.aliyuncs.com'
    url = f'https://{host}/{workspace_id}/data/textFile'
    
    # stream = read_from_file_path('/Users/Downloads/房屋租赁合同1101.docx')
    body = {
        'ClientToken': generate_client_token(),
        'CreateTime': get_create_time(), # Unix时间戳
        'TextFileUrl': ur,# 文件URL
        'TextFileName': file_name
    }
    print(f"The file url is {body['TextFileUrl']} whereas the file name {body['TextFileName']}\n\n")
    
    now = datetime.utcnow()
    timestamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    headers = {
        'host': host,
        'Content-Type': 'application/json',
        'x-acs-action': 'CreateTextFile',
        'x-acs-version': '2024-06-28',
        'x-acs-date': timestamp
    }
    method = 'POST'

    authorization = ali_sign(access_key_id, access_key_secret, url, method, headers, body)
    headers['Authorization'] = authorization

    response = requests.post(url, headers=headers, json=body)
    if response.status_code != 200:
        raise Exception(f"Request failed with status code {response.status_code}: {response.text}")
    
    responseJs=json.loads(response.text)
    print("Uploading Done")
    return responseJs

# resp=generate_message()
# print(resp['Data']['TextFileId'])