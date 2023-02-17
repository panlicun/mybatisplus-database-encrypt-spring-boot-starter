package io.github.panlicun.encrypt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties({EncryptProp.class})
@ConfigurationProperties(
        prefix = "encrypt"
)
public class EncryptProp {
    private Boolean enable = true;
    private String key = null;
    private String type = "default";


    public Boolean getEnable() {
        return enable;
    }

    public void setEnable(Boolean enable) {
        this.enable = enable;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }
}
