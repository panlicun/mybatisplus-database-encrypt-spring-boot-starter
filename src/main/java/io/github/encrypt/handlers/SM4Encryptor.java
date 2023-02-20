package io.github.encrypt.handlers;

import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;

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


    @Override
    public String encrypt(String str) {
        SymmetricCrypto sm4 = new SymmetricCrypto("SM4/ECB/PKCS5Padding",key.getBytes());
        return sm4.encryptHex(str);
    }

    @Override
    public String decrypt(String str) {
        SymmetricCrypto sm4 = new SymmetricCrypto("SM4/ECB/PKCS5Padding",key.getBytes());
        return sm4.decryptStr(str);
    }

}
