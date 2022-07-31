import math
import random

#基本运算

    #求最大公因子
def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

    #求乘法逆元
def Extended_Euclidean(a, m):
    if gcd(a, m) != 1 and gcd(a, m) != -1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    if u1 > 0:
        return u1 % m
    else:
        return (u1 + m) % m

    #椭圆曲线上的点的加法
def Add(m, n):
    if (m == 0):
        return n
    if (n == 0):
        return m
    he = []
    if (m != n):
        if (gcd(m[0] - n[0], p) != 1 and gcd(m[0] - n[0], p) != -1):
            return 0
        else:
            k = ((m[1] - n[1]) * Extended_Euclidean(m[0] - n[0], p)) % p
    else:
        k = ((3 * (m[0] ** 2) + a) * Extended_Euclidean(2 * m[1], p)) % p
    x = (k ** 2 - m[0] - n[0]) % p
    y = (k * (m[0] - x) - m[1]) % p
    he.append(x)
    he.append(y)
    return he

    #椭圆曲线上的点的数乘
def Multiply(n, l):
    if n == 0:
        return 0
    if n == 1:
        return l
    t = l
    while (n >= 2):
        t = Add(t, l)
        n = n - 1
    return t

#ECDSA签名
def ECDSA_Sign(m, n, G, d,k):
    e = hash(m)
    R = Multiply(k, G)
    r = R[0] % n
    s = (Extended_Euclidean(k, n) * (e + d * r)) % n
    return r, s

#ECDSA验证
def ECDSA_Verify(m, n, G, r, s, P):
    e = hash(m)
    w = Extended_Euclidean(s, n)
    v1 = (e * w) % n
    v2 = (r * w) % n
    w = Add(Multiply(v1, G), Multiply(v2, P))
    if (w == 0):
        print('false')
        return False
    else:
        if (w[0] % n == r):
            print('Got it!!!')
            return True
        else:
            print('EORROR!!!')
            return False


#不验证m的验证算法
def Verify_without_m(e, n, G, r, s, P):
    w = Extended_Euclidean(s, n)
    v1 = (e * w) % n
    v2 = (r * w) % n
    w = Add(Multiply(v1, G), Multiply(v2, P))
    if (w == 0):
        print('ERROR!!!')
        return False
    else:
        if (w[0] % n == r):
            print('Got it!!!')
            return True
        else:
            print('ERROR')
            return False

def Pretend(r, s, n, G, P):
    u = random.randrange(1, n - 1)
    v = random.randrange(1, n - 1)
    r1 = Add(Multiply(u, G), Multiply(v, P))[0]
    e1 = (r1 * u * Extended_Euclidean(v, n)) % n
    s1 = (r1 * Extended_Euclidean(v, n)) % n
    Verify_without_m(e1, n, G, r1, s1, P)


#初始化
a = 2
b = 2
p = 17
m = 'high'
m_1 = "grade"
G = [5, 1]
n = 19
k = 2
d = 5
P = Multiply(d, G)


#测试签名和验证
r,s=ECDSA_Sign(m,n,G,d,k)
print("签名为:",r,s)
print("验证结果为：")
ECDSA_Verify(m,n,G,r,s,P)
print('\n')
Pretend(r,s,n,G,P)
print('\n')
