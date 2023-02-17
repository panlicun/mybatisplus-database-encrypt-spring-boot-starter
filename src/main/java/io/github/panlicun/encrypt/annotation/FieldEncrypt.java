package io.github.panlicun.encrypt.annotation;

import java.lang.annotation.*;

/**
 * 加密
 *
 * @author yejunxi
 */
@Documented
@Inherited
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface FieldEncrypt {


}
