package io.github.panlicun.encrypt.handlers;

/**
 * @author yejunxi 2022/09/23
 */
public interface IEncryptor {

    String encrypt(String str);

    String decrypt(String str);
}
