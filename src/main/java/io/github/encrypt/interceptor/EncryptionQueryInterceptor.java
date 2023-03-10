package io.github.encrypt.interceptor;


import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.lang.Pair;
import cn.hutool.core.util.ReflectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.core.util.TypeUtil;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.core.conditions.AbstractWrapper;
import com.baomidou.mybatisplus.core.conditions.segments.MergeSegments;
import com.baomidou.mybatisplus.core.toolkit.PluginUtils;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import io.github.encrypt.annotation.FieldEncrypt;
import io.github.encrypt.bean.Encrypted;
import io.github.encrypt.config.EncryptProp;
import io.github.encrypt.handlers.IEncryptor;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import net.sf.jsqlparser.expression.Expression;
import net.sf.jsqlparser.expression.ExpressionVisitorAdapter;
import net.sf.jsqlparser.expression.operators.conditional.AndExpression;
import net.sf.jsqlparser.expression.operators.relational.EqualsTo;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.schema.Column;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.binding.MapperMethod;
import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.SystemMetaObject;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.Type;
import java.sql.Connection;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@Intercepts({@Signature(type = StatementHandler.class, method = "prepare", args = {Connection.class, Integer.class})})
public class EncryptionQueryInterceptor extends EncryptionBaseInterceptor implements Interceptor {

    /**
     * ?????????<?????????classPath,????????????????????????????????????>
     */
    private static final Map<String, List<String>> ENCRYPT_FIELD_CACHE = new ConcurrentHashMap<>();
    /**
     * ?????????<?????????classPath,Pair<MapperClass, EntityClass>>
     */
    private static final Map<String, Pair<Class, Class>> MAPPED_CLASS_CACHE = new ConcurrentHashMap<>();
    /**
     * ?????????<mapper????????????????????????????????????> ??????????????????String??????????????????
     */
    private static final Map<String, List<String>> MAPPED_METHOD_CACHE = new ConcurrentHashMap<>();

    public EncryptionQueryInterceptor(EncryptProp encryptProp, IEncryptor encryptor) {
        super(encryptProp, encryptor);
    }


    @Override
    public void setProperties(Properties properties) {

    }

    @Override
    public Object plugin(Object target) {
        if (target instanceof StatementHandler) {
            return Plugin.wrap(target, this);
        }
        return target;
    }


    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        StatementHandler statementHandler = PluginUtils.realTarget(invocation.getTarget());
        MetaObject metaObject = SystemMetaObject.forObject(statementHandler);
        MappedStatement mappedStatement = (MappedStatement) metaObject.getValue("delegate.mappedStatement");
        if (!isSelcet(mappedStatement)) {
            return invocation.proceed();
        }
        Object parameterObject = metaObject.getValue("delegate.boundSql.parameterObject");

        if (parameterObject instanceof Encrypted) {
            //????????????Mapper+??????????????????
            this.handleMapperObjectQuery(parameterObject);
        } else if (parameterObject instanceof MapperMethod.ParamMap) {
            MapperMethod.ParamMap paramMap = (MapperMethod.ParamMap) parameterObject;
            if (paramMap.containsKey("ew")) {
                //??????mybatis-plus????????????
                this.handleMybatisPlusQuery(mappedStatement, parameterObject);
            }
            //????????????Mapper+?????????????????????
            else {
                this.handleMapperParamQuery(mappedStatement, parameterObject);
            }
        }

        return invocation.proceed();
    }

    /**
     * ????????????Mapper+??????????????????
     */
    @SneakyThrows
    private void handleMapperObjectQuery(Object parameterObject) {
        Encrypted entity = (Encrypted) parameterObject;
        this.encrypt(entity);
    }

    /**
     * ????????????Mapper+?????????????????????
     */
    @SneakyThrows
    private void handleMapperParamQuery(MappedStatement mappedStatement, Object parameterObject) {
        String methodName = mappedStatement.getId();
        MapperMethod.ParamMap<Object> paramMap = (MapperMethod.ParamMap) parameterObject;
        if(!containsPage(paramMap)){
            for (Map.Entry<String, Object> param : paramMap.entrySet()) {
                if (param.getValue() instanceof Encrypted) {
                    if (param.getKey().contains("param")) {
                        Encrypted entity = (Encrypted) param.getValue();
                        this.encrypt(entity);
                    }
                }else{
                    List<String> encryptParamList = getEncryptParamByMethod(mappedStatement);
                    if (encryptParamList.contains(param.getKey()) && param.getValue() != null) {
                        paramMap.put(param.getKey(), this.encrypt(param.getValue().toString()));
                    }
                }
            }
        }else{
            if (methodName.contains("_mpCount")) {
                for (Map.Entry<String, Object> param : paramMap.entrySet()) {
                    if (param.getValue() instanceof Encrypted) {
                        if (param.getKey().contains("param")) {
                            Encrypted entity = (Encrypted) param.getValue();
                            this.encrypt(entity);
                        }
                    }else{
                        List<String> encryptParamList = getEncryptParamByMethod(mappedStatement);
                        if (encryptParamList.contains(param.getKey()) && param.getValue() != null) {
                            paramMap.put(param.getKey(), this.encrypt(param.getValue().toString()));
                        }
                    }
                }
            }
        }

//        List<String> encryptParamList = getEncryptParamByMethod(mappedStatement);
//        MapperMethod.ParamMap<Object> paramMap = (MapperMethod.ParamMap) parameterObject;
//        for (Map.Entry<String, Object> param : paramMap.entrySet()) {
//            if (encryptParamList.contains(param.getKey()) && param.getValue() != null) {
//                paramMap.put(param.getKey(), this.encrypt(param.getValue().toString()));
//            }
//        }
    }

    private boolean containsPage(MapperMethod.ParamMap<Object> paramMap){
        for (Map.Entry<String, Object> param : paramMap.entrySet()) {
            if(param.getValue() instanceof Page){
                return true;
            }
        }
        return false;
    }

    /**
     * ??????mybatis-plus????????????
     */
    private void handleMybatisPlusQuery(MappedStatement mappedStatement, Object parameterObject) {
        List<String> encryptFields = getEntityEncryptFields(mappedStatement);
        if (CollUtil.isEmpty(encryptFields)) {
            return;
        }
        MapperMethod.ParamMap paramMap = (MapperMethod.ParamMap) parameterObject;
        AbstractWrapper ew = (AbstractWrapper) paramMap.get("ew");
        if (ew == null) {
            return;
        }
        String methodName = mappedStatement.getId();
        MergeSegments expression = ew.getExpression();
        if (expression != null) {
            String whereSql = expression.getSqlSegment();
            if (StringUtils.isEmpty(whereSql)) {
                return;
            }
            Map<String, Object> paramNameValuePairs = ew.getParamNameValuePairs();
            Map<String, ColumMapping> columMappingMap = analysisWhereSql(whereSql, paramNameValuePairs);
            for (String encryptField : encryptFields) {
                ColumMapping columMapping = columMappingMap.get(encryptField);
                if (columMapping != null) {
                    if (methodName.contains("_mpCount")) {
                        paramNameValuePairs.put(columMapping.getAliasName(), this.encrypt(columMapping.getVal()));
                    }
                }
            }
        }
    }


    /**
     * ?????? whereSql
     *
     * @param whereSql
     * @param paramNameValuePairs
     * @return
     */
    private Map<String, ColumMapping> analysisWhereSql(String whereSql, Map<String, Object> paramNameValuePairs) {
        Map<String, String> aliasNameMap = parseParamAliasNameMap(whereSql);
        Map<String, ColumMapping> columMap = new HashMap<>();
        for (Map.Entry<String, Object> item : paramNameValuePairs.entrySet()) {
            //????????????
            String aliasName = item.getKey();
            //?????????
            String val = item.getValue() != null ? item.getValue().toString() : null;
            //?????????
            String columnName = aliasNameMap.get(aliasName);
            columMap.put(
                    columnName,
                    new ColumMapping()
                            .setAliasName(aliasName)
                            .setVal(val)
            );
        }

        return columMap;
    }

    /**
     * ????????????????????????????????????
     *
     * @return
     */
    private List<String> getEncryptParamByMethod(MappedStatement mappedStatement) {
        String id = mappedStatement.getId();
        List<String> list = MAPPED_METHOD_CACHE.get(id);
        if (CollUtil.isEmpty(list)) {
            String[] split = id.split("\\.");
            String methodName = split.length != 0 ? split[split.length - 1] : id;
            Class clazz = getEntityClass(mappedStatement).getKey();
            if (methodName.contains("_mpCount")) {
                methodName = methodName.replace("_mpCount", "");
            }
            Method method = getMethodByName(clazz, methodName);
            list = new ArrayList<>();
            if (method != null) {
                for (Parameter p : method.getParameters()) {
                    if (p.isAnnotationPresent(FieldEncrypt.class) && p.getType() == String.class) {
                        Param param = p.getAnnotation(Param.class);
                        list.add(param != null ? param.value() : p.getName());
                    }
                }
            }
            MAPPED_METHOD_CACHE.put(id, list);
        }
        return list;
    }

    /**
     * ??????Mybatis-plus???whereSql?????????????????????????????????????????????map
     *
     * @return ??????, ?????????
     */
    @SneakyThrows
    private Map<String, String> parseParamAliasNameMap(String whereSql) {
        whereSql = whereSql
                .replaceAll("#", "")
                .replaceAll("\\$", "")
                .replaceAll("\\(", "")
                .replaceAll("\\)", "")
                .replaceAll("\\{", "")
                .replaceAll("}", "")
                .replaceAll("ew.paramNameValuePairs.", "");
        Expression expression = CCJSqlParserUtil.parseCondExpression(whereSql);

        Map<String, String> res = new HashMap<>();
        expression.accept(new ExpressionVisitorAdapter() {
            @Override
            public void visit(AndExpression expr) {
                if (expr.getLeftExpression() instanceof AndExpression) {
                    expr.getLeftExpression().accept(this);
                } else if ((expr.getLeftExpression() instanceof EqualsTo)) {
                    Pair<String, String> pair = getColumnName(expr.getLeftExpression());
                    res.put(pair.getValue(), pair.getKey());
                }
                Pair<String, String> pair = getColumnName(expr.getRightExpression());
                if (null != pair) {
                    res.put(pair.getValue(), pair.getKey());
                }

            }

            @Override
            public void visit(EqualsTo expr) {
                Pair<String, String> pair = getColumnName(expr);
                res.put(pair.getValue(), pair.getKey());
            }
        });
        return res;
    }

    private Method getMethodByName(Class<?> clazz, String methodName) {
        Method[] methods = clazz.getMethods();
        if (methods == null || methods.length == 0) {
            return null;
        }
        for (Method method : methods) {
            if (method.getName().equals(methodName)) {
                return method;
            }
        }
        return null;
    }


    /**
     * ??????where???????????????????????????????????????????????????
     *
     * @param expr
     * @return <?????????,??????> ????????????????????????MPGENVAL1???MPGENVAL2 ...
     */
    private Pair<String, String> getColumnName(Expression expr) {
        if (!(expr instanceof EqualsTo)) {
            return null;
        }
        EqualsTo equalsTo = (EqualsTo) expr;
        String columnName = ((Column) equalsTo.getLeftExpression()).getColumnName();

        String aliasName;
        if (equalsTo.getRightExpression() instanceof Column) {
            aliasName = ((Column) equalsTo.getRightExpression()).getColumnName();
        } else {
            aliasName = equalsTo.getRightExpression().toString();
        }
        return Pair.of(columnName, aliasName);
    }


    /**
     * ?????????????????????????????????????????????????????????list
     *
     * @param mappedStatement
     * @return
     */
    private List<String> getEntityEncryptFields(MappedStatement mappedStatement) {
        String id = mappedStatement.getId();
        List<String> encryptFields = ENCRYPT_FIELD_CACHE.get(id);
        if (encryptFields == null) {
            Class entityClass = getEntityClass(mappedStatement).getValue();
            encryptFields = getEntityEncryptFields(entityClass);
            ENCRYPT_FIELD_CACHE.put(id, encryptFields);
        }
        return encryptFields;
    }

    private List<String> getEntityEncryptFields(Class clazz) {
        Field[] fields = ReflectUtil.getFields(clazz);
        return Arrays.stream(fields)
                .filter(EncryptionQueryInterceptor::isEncryptField)
                .map(e -> {
                    TableField tableField = e.getAnnotation(TableField.class);
                    if (tableField != null && StrUtil.isNotBlank(tableField.value())) {
                        return tableField.value();
                    }
                    //??????????????????
                    return StrUtil.toUnderlineCase(e.getName());
                })
                .collect(Collectors.toList());
    }


    /**
     * ??????EntityClass
     *
     * @param mappedStatement
     * @return mapperClass, entityClass
     */
    @SneakyThrows
    private Pair<Class, Class> getEntityClass(MappedStatement mappedStatement) {
        String id = mappedStatement.getId();
        Pair<Class, Class> pair = MAPPED_CLASS_CACHE.get(id);
        if (pair == null) {
            String classPath = this.getMapperClassPath(mappedStatement);
            Class<?> mapperClass = Class.forName(classPath);
            Type typeArgument = TypeUtil.getTypeArgument(mapperClass, 0);
            Class<?> entityClass = (Class) typeArgument;

            pair = Pair.of(mapperClass, entityClass);
            MAPPED_CLASS_CACHE.put(id, pair);
        }
        return pair;
    }


    @Accessors(chain = true)
    @Data
    public static class ColumMapping {
        private String aliasName;
        private String val;
    }

}