package io.github.panlicun.encrypt.config;

import io.github.panlicun.encrypt.enums.EncryptedType;
import io.github.panlicun.encrypt.handlers.DefaultEncryptor;
import io.github.panlicun.encrypt.handlers.IEncryptor;
import io.github.panlicun.encrypt.handlers.SM4Encryptor;
import io.github.panlicun.encrypt.interceptor.EncryptionQueryInterceptor;
import io.github.panlicun.encrypt.interceptor.EncryptionResultInterceptor;
import io.github.panlicun.encrypt.interceptor.EncryptionSaveInterceptor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

/**
 * @author yejunxi 2022/09/23
 */
@Lazy
@Configuration(
        proxyBeanMethods = false
)
public class EncryptAutoConfiguration {

    @ConditionalOnMissingBean
    @Bean
    public DefaultEncryptor defaultEncryptor(EncryptProp encryptProp) {
        return new DefaultEncryptor(encryptProp.getKey());
    }

    @ConditionalOnMissingBean
    @Bean
    public SM4Encryptor sm4Encryptor(EncryptProp encryptProp) {
        return new SM4Encryptor(encryptProp.getKey());
    }

    @Bean
    public EncryptProp encryptProp() {
        return new EncryptProp();
    }


    @Bean
    public EncryptionResultInterceptor encryptionResultInterceptor(EncryptProp encryptProp) {
        IEncryptor encrypt = getEncrypt(encryptProp);
        return new EncryptionResultInterceptor(encryptProp, encrypt);
    }

    @Bean
    public EncryptionQueryInterceptor encryptionQueryInterceptor(EncryptProp encryptProp) {
        IEncryptor encrypt = getEncrypt(encryptProp);
        return new EncryptionQueryInterceptor(encryptProp, encrypt);
    }

    @Bean
    public EncryptionSaveInterceptor encryptionSaveInterceptor(EncryptProp encryptProp) {
        IEncryptor encrypt = getEncrypt(encryptProp);
        return new EncryptionSaveInterceptor(encryptProp, encrypt);
    }

    private IEncryptor getEncrypt(EncryptProp encryptProp){
        if (encryptProp.getType().equalsIgnoreCase(EncryptedType.AES.getType())) {
            return defaultEncryptor(encryptProp);
        } else if (encryptProp.getType().equalsIgnoreCase(EncryptedType.SM4.getType())) {
            return sm4Encryptor(encryptProp);
        }
        return defaultEncryptor(encryptProp);
    }
}
