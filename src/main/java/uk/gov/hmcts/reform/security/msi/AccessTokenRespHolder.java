package uk.gov.hmcts.reform.security.msi;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AccessTokenRespHolder {

    @JsonProperty(value = "access_token")
    private String accessToken;

    @JsonProperty(value = "client_id")
    private String clientId;

    @JsonProperty(value = "expires_in")
    private String expiresIn;

    @JsonProperty(value = "expires_on")
    private String expiresOn;

    @JsonProperty(value = "ext_expires_in")
    private String extExpiresIn;

    @JsonProperty(value = "not_before")
    private String notBefore;

    @JsonProperty(value = "resource")
    private String resource;

    @JsonProperty(value = "token_type")
    private String tokenType;

    public AccessTokenRespHolder() {
    }

    public AccessTokenRespHolder(String accessToken, String clientId, String expiresIn, String expiresOn,
                                 String extExpiresIn, String notBefore, String resource, String tokenType) {
        this.accessToken = accessToken;
        this.clientId = clientId;
        this.expiresIn = expiresIn;
        this.expiresOn = expiresOn;
        this.extExpiresIn = extExpiresIn;
        this.notBefore = notBefore;
        this.resource = resource;
        this.tokenType = tokenType;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(String expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getExpiresOn() {
        return expiresOn;
    }

    public void setExpiresOn(String expiresOn) {
        this.expiresOn = expiresOn;
    }

    public String getExtExpiresIn() {
        return extExpiresIn;
    }

    public void setExtExpiresIn(String extExpiresIn) {
        this.extExpiresIn = extExpiresIn;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
}
