package io.github.panlicun.encrypt.interceptor;


import cn.hutool.core.util.StrUtil;
import io.github.panlicun.encrypt.annotation.FieldEncrypt;
import io.github.panlicun.encrypt.bean.Encrypted;
import io.github.panlicun.encrypt.config.EncryptProp;
import io.github.panlicun.encrypt.handlers.IEncryptor;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlCommandType;

import java.lang.reflect.Field;

/**
 * @author yejunxi 2022/09/23
 */
public class EncryptionBaseInterceptor {

    /**
     * 加密类
     */
    private final IEncryptor encryptor;

    private EncryptProp encryptProp;

    public EncryptionBaseInterceptor(EncryptProp encryptProp, IEncryptor encryptor) {
        this.encryptProp = encryptProp;
        this.encryptor = encryptor;
    }

    public String encrypt(String str) {
        if(!encryptProp.getEnable()){
            return str;
        }
        return encryptor.encrypt(str);
    }

    public String decrypt(String str) {
        if(!encryptProp.getEnable()){
            return str;
        }
        return encryptor.decrypt(str);
    }

    public void encrypt(Field field, Object object) throws IllegalAccessException {
        String fieldStr = getFieldStr(field, object);
        if (fieldStr != null) {
            field.setAccessible(true);
            field.set(object, encrypt(fieldStr));
        }
    }

    public void decrypt(Field field, Object object) throws IllegalAccessException {
        String fieldStr = getFieldStr(field, object);
        if (fieldStr != null) {
            field.setAccessible(true);
            field.set(object, decrypt(fieldStr));
        }
    }

    public void encrypt(Encrypted object) throws IllegalAccessException {
        for (Field field : object.getEncryptFields()) {
            if (isEncryptField(field, object)) {
                this.encrypt(field, object);
            }
        }
    }

    public void decrypt(Encrypted object) throws IllegalAccessException {
        for (Field field : object.getEncryptFields()) {
            if (isEncryptField(field, object)) {
                this.decrypt(field, object);
            }
        }
    }


    public String getFieldStr(Field field, Object object) throws IllegalAccessException {
        Object val = field.get(object);
        if (val == null || StrUtil.isBlank(val.toString())) {
            return null;
        }
        return val.toString();
    }


    public static boolean isEncryptField(Field field) {
        return field.isAnnotationPresent(FieldEncrypt.class);
    }

    public static boolean isEncryptField(Field field, Object obj) throws IllegalAccessException {
        return isEncryptField(field) && field.get(obj) instanceof String;
    }

    public static boolean isInsertOrUpdate(MappedStatement mappedStatement) {
        SqlCommandType type = mappedStatement.getSqlCommandType();
        return SqlCommandType.UPDATE == type || SqlCommandType.INSERT == type;
    }

    public static boolean isSelcet(MappedStatement mappedStatement) {
        SqlCommandType type = mappedStatement.getSqlCommandType();
        return SqlCommandType.SELECT == type;
    }

    public String getMapperClassPath(MappedStatement mappedStatement) {
        String classPath = mappedStatement.getId();
        return classPath.substring(0, classPath.lastIndexOf("."));
    }
}
