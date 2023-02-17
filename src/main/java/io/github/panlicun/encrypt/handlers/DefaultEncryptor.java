package io.github.panlicun.encrypt.handlers;

import cn.hutool.crypto.SecureUtil;
import org.springframework.util.StringUtils;

/**
 * 默认加密实现
 *
 * @author yejunxi 2022/09/23
 */
public class DefaultEncryptor implements IEncryptor {

    public DefaultEncryptor(String key) {
        if(!StringUtils.isEmpty(key)){
            this.key = key;
        }
    }

    String key = "!QAZ@WSX#EDC$RFV";

    @Override
    public String encrypt(String str) {
        return SecureUtil.aes(key.getBytes()).encryptHex(str);
    }

    @Override
    public String decrypt(String str) {
        return SecureUtil.aes(key.getBytes()).decryptStr(str);
    }
}
