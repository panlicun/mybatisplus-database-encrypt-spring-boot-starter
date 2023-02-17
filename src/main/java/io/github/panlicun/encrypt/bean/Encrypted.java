package io.github.panlicun.encrypt.bean;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.github.panlicun.encrypt.annotation.FieldEncrypt;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;


public interface Encrypted {

    @JsonIgnore
    default List<Field> getEncryptFields() {
        List<Field> list = new ArrayList<>();
        Field[] fields = this.getClass().getDeclaredFields();
        for (Field field : fields) {
            field.setAccessible(true);
            if (field.isAnnotationPresent(FieldEncrypt.class)) {
                list.add(field);
            }
        }
        return list;
    }
}
