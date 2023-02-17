package io.github.encrypt.annotation;

import java.lang.annotation.*;

/**
 * 加密
 *
 * @author plc
 */
@Documented
@Inherited
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface FieldEncrypt {


}
