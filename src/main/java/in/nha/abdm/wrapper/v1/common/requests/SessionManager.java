/* (C) 2024 */
package in.nha.abdm.wrapper.v1.common.requests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import in.nha.abdm.wrapper.ApplicationConfig;
import in.nha.abdm.wrapper.v1.common.Utils;
import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutException;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import reactor.core.Exceptions;
import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.ProxyProvider;
import reactor.util.retry.Retry;

@Component
public class SessionManager {

  @Autowired ApplicationConfig applicationConfig;
  private volatile String accessToken;
  private volatile Instant accessTokenExpiresAt;

  // Used when the gateway response has no "expiresIn". Upstream noted 20-minute tokens.
  private static final long DEFAULT_TOKEN_TTL_SECONDS = 15 * 60;

  @Value("${anvaya.session.refresh-skew-seconds:120}")
  private long refreshSkewSeconds;

  @Value("${gatewayBaseUrl}")
  private String gatewayBaseUrl;

  @Value("${createSessionPath}")
  private String createSessionPath;

  @Value("${useProxySettings}")
  private boolean useProxySettings;

  @Value("${proxyHost}")
  private String proxyHost;

  @Value("${proxyPort}")
  private int proxyPort;

  @Value("${connectionTimeout}")
  private int connectionTimeout;

  @Value("${responseTimeout}")
  private int responseTimeout;

  private static final Logger log = LogManager.getLogger(SessionManager.class);

  private static final String CONSENT_MANAGER_ENVIRONMENT = "X-CM-ID";
  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String TIMESTAMP = "TIMESTAMP";
  private static final String REQUEST_ID = "REQUEST-ID";

  public HttpHeaders setGatewayRequestHeaders() {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.add(CONSENT_MANAGER_ENVIRONMENT, applicationConfig.environment);
    headers.add(AUTHORIZATION_HEADER, this.fetchAccessToken());
    return headers;
  }

  public HttpHeaders setDefaultSessionHeaders() {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.add(CONSENT_MANAGER_ENVIRONMENT, applicationConfig.environment);
    headers.add(TIMESTAMP, Utils.getCurrentTimeStamp());
    headers.add(REQUEST_ID, UUID.randomUUID().toString());
    return headers;
  }

  /**
   * Anvaya: returns a valid token, refreshing it lazily when it is missing or within {@code
   * refreshSkewSeconds} of expiry. Upstream relied on a 15-minute @Scheduled refresh, which does
   * not fire reliably on Cloud Run when CPU is throttled between requests, so tokens went stale.
   */
  private String fetchAccessToken() {
    if (isTokenUsable()) {
      return accessToken;
    }
    synchronized (this) {
      if (!isTokenUsable()) {
        try {
          startSession();
        } catch (Throwable e) {
          throw new RuntimeException("Could not obtain ABDM gateway session", e);
        }
      }
      return accessToken;
    }
  }

  private boolean isTokenUsable() {
    Instant expiry = accessTokenExpiresAt;
    return accessToken != null
        && expiry != null
        && Instant.now().isBefore(expiry.minusSeconds(refreshSkewSeconds));
  }

  /**
   * Anvaya: drop a token the gateway rejected (HTTP 401) so the next call opens a new session. Only
   * clears it if it is still the current token, so a concurrent refresh is not thrown away.
   */
  public synchronized void invalidateToken(String rejectedToken) {
    if (rejectedToken != null && rejectedToken.equals(accessToken)) {
      log.warn("Gateway rejected the session token; it will be refreshed on next use");
      accessToken = null;
      accessTokenExpiresAt = null;
    }
  }

  /** Current "Bearer ..." header value (refreshing if needed). */
  public String currentAuthorizationHeader() {
    return fetchAccessToken();
  }

  /**
   * Opens a gateway session and stores the token with its expiry (from "expiresIn", in seconds).
   * Transient network/5xx errors are retried inside {@link #getSessionResponse}.
   */
  public synchronized void startSession() throws Throwable {

    CreateSessionRequest createSessionRequest =
        CreateSessionRequest.builder()
            .clientId(applicationConfig.clientId)
            .clientSecret(applicationConfig.clientSecret)
            .grantType("client_credentials")
            .build();
    try {

      ResponseEntity<ObjectNode> responseEntity = getSessionResponse(createSessionRequest);
      ObjectNode body = responseEntity.getBody();
      JsonNode tokenNode = body == null ? null : body.findValue("accessToken");
      if (tokenNode == null || tokenNode.asText().isBlank()) {
        // Do not log the body: it may contain credentials.
        log.error("Empty access token in response from " + createSessionPath);
        throw new IllegalStateException("Gateway session response had no accessToken");
      }
      JsonNode expiresInNode = body.findValue("expiresIn");
      long expiresIn =
          expiresInNode != null && expiresInNode.asLong() > 0
              ? expiresInNode.asLong()
              : DEFAULT_TOKEN_TTL_SECONDS;
      accessToken = MessageFormat.format("Bearer {0}", tokenNode.asText());
      accessTokenExpiresAt = Instant.now().plusSeconds(expiresIn);
      log.info("Gateway session opened; token valid for " + expiresIn + "s");
    } catch (Exception e) {
      log.error("Could not start gateway session: " + e);
      // This is to get actual exception wrapped under ReactiveException.
      throw Exceptions.unwrap(e);
    }
  }

  private ResponseEntity<ObjectNode> getSessionResponse(CreateSessionRequest createSessionRequest) {
    WebClient webClient =
        WebClient.builder()
            .baseUrl(gatewayBaseUrl)
            .defaultHeaders(httpHeaders -> httpHeaders.addAll(setDefaultSessionHeaders()))
            .clientConnector(new ReactorClientHttpConnector(getHttpClient(useProxySettings)))
            .build();

    return webClient
        .post()
        .uri(createSessionPath)
        .body(BodyInserters.fromValue(createSessionRequest))
        .retrieve()
        .toEntity(ObjectNode.class)
        .retryWhen(
            Retry.backoff(5, Duration.ofSeconds(2))
                .filter(
                    throwable ->
                        throwable instanceof HttpServerErrorException
                            || throwable instanceof WebClientRequestException
                            || throwable instanceof ReadTimeoutException
                            || throwable instanceof java.util.concurrent.TimeoutException))
        .block();
  }

  public HttpClient getHttpClient(boolean useProxySettings) {
    HttpClient httpClient;
    if (useProxySettings) {
      httpClient =
          HttpClient.create()
              .responseTimeout(Duration.ofSeconds(responseTimeout))
              .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectionTimeout)
              .tcpConfiguration(
                  tcpClient ->
                      tcpClient.proxy(
                          proxy ->
                              proxy
                                  .type(ProxyProvider.Proxy.HTTP)
                                  .host(proxyHost)
                                  .port(proxyPort)));
    } else {
      httpClient =
          HttpClient.create()
              .responseTimeout(Duration.ofSeconds(responseTimeout))
              .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectionTimeout);
    }
    return httpClient;
  }
}
