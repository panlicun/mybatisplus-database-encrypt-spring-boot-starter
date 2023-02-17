package io.github.panlicun.encrypt.interceptor;

import cn.hutool.core.collection.CollUtil;
import io.github.panlicun.encrypt.bean.Encrypted;
import io.github.panlicun.encrypt.config.EncryptProp;
import io.github.panlicun.encrypt.handlers.IEncryptor;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Signature;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;

import java.util.ArrayList;

/**
 * 查询结果解密拦截器
 *
 * @author yejunxi 2022/09/23
 */
@Slf4j
@Intercepts({
        @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class}),
        @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class, CacheKey.class, BoundSql.class}),
})
public class EncryptionResultInterceptor extends EncryptionBaseInterceptor implements Interceptor {


    public EncryptionResultInterceptor(EncryptProp encryptProp,IEncryptor encryptor) {
        super(encryptProp,encryptor);
    }

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        Object result = invocation.proceed();
        if (result instanceof ArrayList) {
            ArrayList list = (ArrayList) result;
            if (CollUtil.isNotEmpty(list) && list.get(0) instanceof Encrypted) {
                for (Object item : list) {
                    this.decrypt((Encrypted) item);
                }
            }
        } else if (result instanceof Encrypted) {
            this.decrypt((Encrypted) result);
        }
        return result;
    }
}
