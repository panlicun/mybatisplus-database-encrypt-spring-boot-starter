package io.github.panlicun.encrypt.handlers;

import cn.hutool.crypto.symmetric.SymmetricCrypto;
import org.springframework.util.StringUtils;

/**
 * SM4加密
 */
public class SM4Encryptor implements IEncryptor {

    String key = "!QAZ@WSX#EDC$RFV";

    public SM4Encryptor(String key) {
        if(!StringUtils.isEmpty(key)){
            this.key = key;
        }
    }

    SymmetricCrypto sm4 = new SymmetricCrypto("SM4/ECB/PKCS5Padding",key.getBytes());

    @Override
    public String encrypt(String str) {
        return sm4.encryptHex(str);
    }

    @Override
    public String decrypt(String str) {
        return sm4.decryptStr(str);
    }

}
