package io.github.panlicun.encrypt.interceptor;


import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.lang.Pair;
import cn.hutool.core.util.ReflectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.core.util.TypeUtil;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.core.conditions.AbstractWrapper;
import com.baomidou.mybatisplus.core.conditions.segments.MergeSegments;
import com.baomidou.mybatisplus.core.toolkit.PluginUtils;
import io.github.panlicun.encrypt.annotation.FieldEncrypt;
import io.github.panlicun.encrypt.bean.Encrypted;
import io.github.panlicun.encrypt.config.EncryptProp;
import io.github.panlicun.encrypt.handlers.IEncryptor;
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
     * 缓存：<实体类classPath,实体类对应需要加密的字段>
     */
    private static final Map<String, List<String>> ENCRYPT_FIELD_CACHE = new ConcurrentHashMap<>();
    /**
     * 缓存：<实体类classPath,Pair<MapperClass, EntityClass>>
     */
    private static final Map<String, Pair<Class, Class>> MAPPED_CLASS_CACHE = new ConcurrentHashMap<>();
    /**
     * 缓存：<mapper方法名，需要加密的参数名> （特指参数是String类型的方法）
     */
    private static final Map<String, List<String>> MAPPED_METHOD_CACHE = new ConcurrentHashMap<>();

    public EncryptionQueryInterceptor(EncryptProp encryptProp,IEncryptor encryptor) {
        super(encryptProp,encryptor);
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
            //处理原生Mapper+对象入参查询
            this.handleMapperObjectQuery(parameterObject);
        } else if (parameterObject instanceof MapperMethod.ParamMap) {
            MapperMethod.ParamMap paramMap = (MapperMethod.ParamMap) parameterObject;
            if (paramMap.containsKey("ew")) {
                //处理mybatis-plus单表查询
                this.handleMybatisPlusQuery(mappedStatement, parameterObject);
            }
            //处理原生Mapper+字符串入参查询
            else {
                this.handleMapperParamQuery(mappedStatement, parameterObject);
            }
        }

        return invocation.proceed();
    }

    /**
     * 处理原生Mapper+对象入参查询
     */
    @SneakyThrows
    private void handleMapperObjectQuery(Object parameterObject) {
        Encrypted entity = (Encrypted) parameterObject;
        this.encrypt(entity);
    }

    /**
     * 处理原生Mapper+字符串入参查询
     */
    @SneakyThrows
    private void handleMapperParamQuery(MappedStatement mappedStatement, Object parameterObject) {
        List<String> encryptParamList = getEncryptParamByMethod(mappedStatement);
        MapperMethod.ParamMap<Object> paramMap = (MapperMethod.ParamMap) parameterObject;
        for (Map.Entry<String, Object> param : paramMap.entrySet()) {
            if (encryptParamList.contains(param.getKey()) && param.getValue() != null) {
                paramMap.put(param.getKey(), this.encrypt(param.getValue().toString()));
            }
        }
    }

    /**
     * 处理mybatis-plus单表查询
     */
    private void handleMybatisPlusQuery(MappedStatement mappedStatement, Object parameterObject) {
        List<String> encryptFields = getEntityEncryptFields(mappedStatement);
        if (CollUtil.isEmpty(encryptFields)) {
            return;
        }
        MapperMethod.ParamMap paramMap = (MapperMethod.ParamMap) parameterObject;
        AbstractWrapper ew = (AbstractWrapper) paramMap.get("ew");
        MergeSegments expression = ew.getExpression();
        if (expression != null) {
            String whereSql = expression.getSqlSegment();
            Map<String, Object> paramNameValuePairs = ew.getParamNameValuePairs();
            Map<String, ColumMapping> columMappingMap = analysisWhereSql(whereSql, paramNameValuePairs);
            for (String encryptField : encryptFields) {
                ColumMapping columMapping = columMappingMap.get(encryptField);
                if (columMapping != null) {
                    paramNameValuePairs.put(columMapping.getAliasName(), this.encrypt(columMapping.getVal()));
                }
            }
        }
    }


    /**
     * 解析 whereSql
     *
     * @param whereSql
     * @param paramNameValuePairs
     * @return
     */
    private Map<String, ColumMapping> analysisWhereSql(String whereSql, Map<String, Object> paramNameValuePairs) {
        Map<String, String> aliasNameMap = parseParamAliasNameMap(whereSql);
        Map<String, ColumMapping> columMap = new HashMap<>();
        for (Map.Entry<String, Object> item : paramNameValuePairs.entrySet()) {
            //参数别名
            String aliasName = item.getKey();
            //参数值
            String val = item.getValue() != null ? item.getValue().toString() : null;
            //字段名
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
     * 获取某方法需要加密的入参
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
            Method method = ReflectUtil.getMethodByName(clazz, methodName);
            list = new ArrayList<>();
            for (Parameter p : method.getParameters()) {
                if (p.isAnnotationPresent(FieldEncrypt.class) && p.getType() == String.class) {
                    Param param = p.getAnnotation(Param.class);
                    list.add(param != null ? param.value() : p.getName());
                }
            }
            MAPPED_METHOD_CACHE.put(id, list);
        }
        return list;
    }

    /**
     * 根据Mybatis-plus的whereSql获得一个参数别名与字段名的映射map
     *
     * @return 别名, 字段名
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
                res.put(pair.getValue(), pair.getKey());
            }

            @Override
            public void visit(EqualsTo expr) {
                Pair<String, String> pair = getColumnName(expr);
                res.put(pair.getValue(), pair.getKey());
            }
        });
        return res;
    }


    /**
     * 返回where表达式中，字段名与参数名的映射关系
     *
     * @param expr
     * @return <字段名,别名> ，参数别名特指：MPGENVAL1、MPGENVAL2 ...
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
     * 获取本次查询的实体类所需要加密的字段名list
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
                    //驼峰转下划线
                    return StrUtil.toUnderlineCase(e.getName());
                })
                .collect(Collectors.toList());
    }


    /**
     * 获取EntityClass
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