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

    SymmetricCrypto sm4 = SmUtil.sm4(key.getBytes(StandardCharsets.UTF_8));

    @Override
    public String encrypt(String str) {
        return sm4.encryptHex(str);
    }

    @Override
    public String decrypt(String str) {
        return sm4.decryptStr(str);
    }

}
