package io.github.encrypt.interceptor;


import io.github.encrypt.bean.Encrypted;
import io.github.encrypt.config.EncryptProp;
import io.github.encrypt.handlers.IEncryptor;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Signature;

import java.util.Map;

/**
 * 保存数据加密库拦截器
 *
 * @author yejunxi 2022/09/23
 */
@Slf4j
@Intercepts({
        @Signature(method = "update", type = Executor.class, args = {MappedStatement.class, Object.class}),
})
public class EncryptionSaveInterceptor extends EncryptionBaseInterceptor implements Interceptor {


    public EncryptionSaveInterceptor(EncryptProp encryptProp, IEncryptor encryptor) {
        super(encryptProp, encryptor);
    }


    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        Object[] args = invocation.getArgs();
        MappedStatement mappedStatement = (MappedStatement) args[0];
        Object entity = args[1];
        if(isInsertOrUpdate(mappedStatement)){
            if (entity instanceof Map) {
                Map map = (Map) entity;
                Object et = map.getOrDefault("et", (Object) null);
                if (et != null) {
                    this.encrypt((Encrypted) et);
                }
            }else{
                this.encrypt((Encrypted) entity);
            }
        }
        return invocation.proceed();

    }

}
