from array import array
Tj_rl = array('L', ((0x79cc4519 << j | 0x79cc4519 >> 32-j) & 0xffffffff for j in range(16)))
Tj_rl.extend((0x7a879d8a << (j & 31) | 0x7a879d8a >> (32 - j & 31)) & 0xffffffff for j in range(16, 64))
V0 = array('L', [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e])
 
 
def CF(V, B):
    W = array('L', B)
    for j in range(16, 68):
        X = W[j-16] ^ W[j-9] ^ (W[j-3] << 15 | W[j-3] >> 17) & 0xffffffff
        W.append((X ^ (X << 15 | X >> 17) ^ (X << 23 | X >> 9) ^ (W[j-13] << 7 | W[j-13] >> 25) ^ W[j-6]) & 0xffffffff)
    W_ = array('L', (W[j] ^ W[j+4] for j in range(64)))
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        A_rl12 = A << 12 | A >> 20
        tmp = (A_rl12 + E + Tj_rl[j]) & 0xffffffff
        SS1 = (tmp << 7 | tmp >> 25)
        SS2 = SS1 ^ A_rl12
        if j & 0x30:  # 16 <= j
            FF, GG = A & B | A & C | B & C, E & F | ~E & G
        else:
            FF, GG = A ^ B ^ C, E ^ F ^ G
        TT1, TT2 = (FF + D + SS2 + W_[j]) & 0xffffffff, (GG + H + SS1 + W[j]) & 0xffffffff
        C, D, G, H = (B << 9 | B >> 23) & 0xffffffff, C, (F << 19 | F >> 13) & 0xffffffff, G
        A, B, E, F = TT1, A, (TT2 ^ (TT2 << 9 | TT2 >> 23) ^ (TT2 << 17 | TT2 >> 15)) & 0xffffffff, E
    return A ^ V[0], B ^ V[1], C ^ V[2], D ^ V[3], E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]
 
 
def Digest(data):
    # 填充
    pad_num = 64 - (len(data) + 1 & 0x3f)
    data += b'\x80' + (len(data) << 3).to_bytes(pad_num if pad_num >= 8 else pad_num + 64, 'big')
    V, B = V0, array('L', data)
    B.byteswap()
    # 迭代压缩
    for i in range(0, len(B), 16):
        V = CF(V, B[i:i+16])
    V = array('L', V)
    V.byteswap()
    return V.tobytes()
 
from gmssl.sm3 import sm3_hash
import time, os
 
def gmssl(data: bytes) -> bytes:
    return bytes.fromhex(sm3_hash([i for i in data]))
 
def Optimized(data: bytes) -> bytes:
    return Digest(data)
 
def Comparison():
    # 随机生成消息
    long_data = os.urandom(128)
    # gmssl
    time_1 = time.perf_counter()
    gmssl(long_data)
    time_2 = time.perf_counter()
    hash2 = gmssl(long_data)
    time_3 = time.perf_counter()
    print('gmssl\t\t%.1f\t\t%.1f' % ((time_2 - time_1) * 1000000, (time_3 - time_2) * 1000000))
    assert hash1 == hash2
    # Optimized
    time_1 = time.perf_counter()
    Optimized(long_data)
    time_2 = time.perf_counter()
    hash2 = Optimized(long_data)
    time_3 = time.perf_counter()
    print('Optimized\t\t\t%.1f\t\t%.1f' % ((time_2 - time_1) * 1000000, (time_3 - time_2) * 1000000))
    assert hash1 == hash2
 
    print('\n—————————————————————↑首次↓连续—————————————————————')
    test_num = 100
    # 随机生成消息
    short_data = [os.urandom(28) for i in range(test_num)]  # 短消息列表
    long_data = [os.urandom(1128) for i in range(test_num)]  # 长消息列表
    hash_data = [b''] * test_num
    hash_data1 = [b''] * test_num
    hash_data2 = [b''] * test_num
    hash_data3 = [b''] * test_num
    hash_data4 = [b''] * test_num
     # gmssl
    time_1 = time.perf_counter()
    for i in range(test_num):
        hash_data1[i] = gmssl(short_data[i])  # 短消息Hash
    time_2 = time.perf_counter()
    for i in range(test_num):
        hash_data2[i] = gmssl(long_data[i])  # 长消息Hash
    time_3 = time.perf_counter()
    print('gmssl\t\t%.2f\t\t%.2f' % ((time_2 - time_1) * 1000, (time_3 - time_2) * 1000))
    time_aim = time_3 - time_1
 
    # Optimized
    time_1 = time.perf_counter()
    for i in range(test_num):
        hash_data1[i] = Optimized(short_data[i])  # 短消息Hash
    time_2 = time.perf_counter()
    for i in range(test_num):
        hash_data2[i] = Optimized(long_data[i])  # 长消息Hash
    time_3 = time.perf_counter()
    print('Optimized\t\t\t%.2f\t\t%.2f' % ((time_2 - time_1) * 1000, (time_3 - time_2) * 1000))
    time_O = time_3 - time_1
    print('运行时间为gmssl的%.2f%%' % (time_O / time_aim * 100))
    assert hash_data1 == hash_data3 and hash_data2 == hash_data4
 
 
if __name__ == "__main__":
    Comparison()
