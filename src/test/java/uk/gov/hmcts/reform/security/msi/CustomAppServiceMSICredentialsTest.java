package uk.gov.hmcts.reform.security.msi;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpBackOffUnsuccessfulResponseHandler;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.util.ExponentialBackOff;
import com.microsoft.azure.AzureEnvironment;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CustomAppServiceMSICredentialsTest {

    private static final String MSI_KEYVAULT_TOKEN_URL =
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net";
    private static final String REQUEST_HEADER_METADATA = "Metadata";
    private static final String REQUEST_HEADER_METADATA_VALUE_TRUE = "true";
    private static final String ACCESS_TOKEN_SOME_ACCESS_TOKEN_VALUE =
        "{\"access_token\": \"some-access-token-value\"}";

    private CustomAppServiceMSICredentials customAppServiceMSICredentials;

    @Mock
    HttpRequestFactory httpRequestFactoryMock;

    @Mock
    ObjectMapper objectMapperMock;

    @Mock
    HttpRequest httpRequestMock;

    @Mock
    HttpResponse httpResponseMock;

    @Before
    public void setup() {
        customAppServiceMSICredentials
                = new CustomAppServiceMSICredentials(AzureEnvironment.AZURE, httpRequestFactoryMock, objectMapperMock);
    }

    @Test
    public void shouldCallRequestExecuteMethodAndParseToken() throws IOException {
        GenericUrl genericUrl = new GenericUrl(MSI_KEYVAULT_TOKEN_URL);
        HttpHeaders headers = new HttpHeaders();
        headers.set(REQUEST_HEADER_METADATA, REQUEST_HEADER_METADATA_VALUE_TRUE);

        AccessTokenRespHolder accessTokenRespHolder = new AccessTokenRespHolder();
        accessTokenRespHolder.setAccessToken(ACCESS_TOKEN_SOME_ACCESS_TOKEN_VALUE);


        when(httpRequestFactoryMock.buildGetRequest(genericUrl)).thenReturn(httpRequestMock);
        when(httpRequestMock.setHeaders(headers)).thenReturn(httpRequestMock);
        when(httpRequestMock.setUnsuccessfulResponseHandler(any())).thenReturn(httpRequestMock);
        when(httpRequestMock.setNumberOfRetries(3)).thenReturn(httpRequestMock);
        when(httpRequestMock.execute()).thenReturn(httpResponseMock);
        when(httpResponseMock.parseAsString()).thenReturn(ACCESS_TOKEN_SOME_ACCESS_TOKEN_VALUE);
        when(objectMapperMock.readValue(ACCESS_TOKEN_SOME_ACCESS_TOKEN_VALUE, AccessTokenRespHolder.class))
                                                                        .thenReturn(accessTokenRespHolder);


        String token = customAppServiceMSICredentials.getToken("resource");

        Assert.assertEquals(token, ACCESS_TOKEN_SOME_ACCESS_TOKEN_VALUE);

    }

    @Test
    public void shouldBuildRequestWithUrlAndHeaderMap() throws IOException {
        //given
        CustomAppServiceMSICredentials credentials = new CustomAppServiceMSICredentials(AzureEnvironment.AZURE);

        //when
        HttpRequest resultHttpRequest = credentials.buildTokenHttpRequest();

        //then
        assertEquals(resultHttpRequest.getUrl().toString(), MSI_KEYVAULT_TOKEN_URL);
        assertEquals(resultHttpRequest.getHeaders().getFirstHeaderStringValue(REQUEST_HEADER_METADATA),
            REQUEST_HEADER_METADATA_VALUE_TRUE);
        assertEquals(resultHttpRequest.getNumberOfRetries(), 3);

        assertNotNull(resultHttpRequest.getUnsuccessfulResponseHandler());

        HttpBackOffUnsuccessfulResponseHandler responseHandler =
            (HttpBackOffUnsuccessfulResponseHandler) resultHttpRequest.getUnsuccessfulResponseHandler();
        ExponentialBackOff backOff = (ExponentialBackOff) responseHandler.getBackOff();

        assertEquals(backOff.getInitialIntervalMillis(), 500);
        assertEquals(backOff.getMaxElapsedTimeMillis(), 90000);
        assertEquals(backOff.getMaxIntervalMillis(), 6000);
        assertEquals(backOff.getMultiplier(), 1.5, 1.5);
        assertEquals(backOff.getRandomizationFactor(), 0.5, 0.5);

    }

}
