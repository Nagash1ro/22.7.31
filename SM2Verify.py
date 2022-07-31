import base64
from gmssl import sm2, func

def test_sm2():
    private_key = '0d1d31b70ef5d8d04d1d58158b2b418321a5b3dc8c68cdfe821a5e8c42d7e201'
    public_key = '36cd1616a0fdf51a57c9ac9c492d1049f8dd2579625814e1ddc9bd8d8de0b251530eced795456dc46802a5b1e1cfb7897ba39045e4619fcee3a0200e2a450ed7'

    print("-----------------test encrypt and decrypt---------------")
    sm2_crypt = sm2.CryptSM2(
        public_key=public_key, private_key=private_key)
    data = b'111'
    data2 = '{"tranAmount":"","payType":"2","cardNo":"1234568888666622208","holderName":"测试","cardAvailableDate":"","cvv2":"","mobileNo":"18911556146","identityType":"1","identityCode":"","bindCrdAgrNo":"","notifyUrl":"https://ncountgray.hnapay.com/callback/test.htm","orderExpireTime":"","userId":"100000006096","receiveUserId":"100000006096","merUserIp":"","riskExpand":"","goodsInfo":"apiTest","subMerchantId":"","merchantId":"127.0.0.1","divideFlag":"","divideDetail":""}'
    newData = data2.encode()
    enc_data = sm2_crypt.encrypt(newData)
    new_encData = base64.b64encode(enc_data)
    print("加密数据转base64结果: \n%s" % str(new_encData).strip('b'))
    # print("enc_data_base64:%s" % base64.b64encode(bytes.fromhex(enc_data)))
    dec_data = sm2_crypt.decrypt(enc_data)
    new_decData = str(dec_data).strip('b')
    print("解密结果:%s \n" % new_decData)
    assert newData == dec_data

    print("-----------------test sign and verify---------------")
    random_hex_str = func.random_hex(sm2_crypt.para_len)

    sign = sm2_crypt.sign(newData, random_hex_str)
    sign2 = sm2_crypt.sign_with_sm3(newData, random_hex_str)
    print('签名值: \n%s ' % sign)
    print('签名值2:\n%s ' % sign2)
    verify = sm2_crypt.verify(sign, newData)
    verify2 = sm2_crypt.verify_with_sm3(sign2, newData)
    print('verify验签结果1:\n%s ' % verify)
    print('verify2验签结果2:%s ' % verify2)
    assert verify
    assert verify2
