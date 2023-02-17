package io.github.panlicun.encrypt.enums;

/**
 * 加密类型
 *
 * @author plc
 */
public enum EncryptedType {

    DEFAULT("default"),
    AES("aes"),
    SM4("sm4");

    private final String type;

    EncryptedType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

}
