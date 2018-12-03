package uk.gov.hmcts.reform.security.msi;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AccessTokenRespHolder {

    @JsonProperty(value = "access_token")
    private String accessToken;

    public AccessTokenRespHolder() {
    }


    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }


}
