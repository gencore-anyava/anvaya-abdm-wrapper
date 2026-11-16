/* (C) 2024 */
package in.nha.abdm.wrapper.v3.common;

import in.nha.abdm.wrapper.v1.common.requests.SessionManager;
import in.nha.abdm.wrapper.v3.common.logger.CurlLogger;
import in.nha.abdm.wrapper.v3.common.models.GenericV3Response;
import io.netty.handler.timeout.ReadTimeoutException;
import java.time.Duration;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.util.retry.Retry;

@Component
public class RequestV3Manager {
  private static final Logger log = LogManager.getLogger(RequestV3Manager.class);

  @Value("${connectionTimeout}")
  private int connectionTimeout;

  @Value("${responseTimeout}")
  private int responseTimeout;

  private final WebClient webClient;
  private final SessionManager sessionManager;

  @Value("${logCurl}")
  private boolean logCurl;

  String gatewayBaseUrlForLog;

  @Autowired
  public RequestV3Manager(
      @Value("${gatewayBaseUrl}") final String gatewayBaseUrl,
      @Value("${useProxySettings}") final boolean useProxySettings,
      SessionManager sessionManager) {
    this.sessionManager = sessionManager;
    this.gatewayBaseUrlForLog = gatewayBaseUrl;
    this.webClient =
        WebClient.builder()
            .baseUrl(gatewayBaseUrl)
            .clientConnector(
                new ReactorClientHttpConnector(sessionManager.getHttpClient(useProxySettings)))
            // Anvaya: no default auth headers. Upstream fetched a session token here, at bean
            // creation, which made startup depend on the gateway and pinned a token that later
            // expired. Gateway headers are set per request below.
            .build();
  }

  // Initializing headers every time to avoid setting the old headers/session token and getting
  // unauthorised error from gateway.
  @Retryable(
      value = {WebClientRequestException.class, ReadTimeoutException.class, TimeoutException.class},
      maxAttempts = 5,
      backoff = @Backoff(delay = 1000, multiplier = 2))
  public <T> ResponseEntity<GenericV3Response> fetchResponseFromGateway(
      String uri, T request, HttpHeaders customHeader) {

    // Logging the headers which has hipId
    log.info(customHeader);

    HttpHeaders gatewayHeaders = sessionManager.setGatewayRequestHeaders();
    try {
      return sendToGateway(uri, request, customHeader, gatewayHeaders);
    } catch (WebClientResponseException.Unauthorized e) {
      // Anvaya: token expired or was revoked early. Drop it, open a new session, retry once.
      log.warn("Gateway returned 401 for " + uri + "; refreshing session and retrying once");
      sessionManager.invalidateToken(gatewayHeaders.getFirst(HttpHeaders.AUTHORIZATION));
      return sendToGateway(uri, request, customHeader, sessionManager.setGatewayRequestHeaders());
    }
  }

  private <T> ResponseEntity<GenericV3Response> sendToGateway(
      String uri, T request, HttpHeaders customHeader, HttpHeaders gatewayHeaders) {
    // Logging the cUrl when needed for debugging
    if (logCurl) {
      CurlLogger.logCurl(gatewayBaseUrlForLog + uri, request, customHeader, gatewayHeaders);
    }
    return webClient
        .post()
        .uri(uri)
        .headers(httpHeaders -> httpHeaders.addAll(customHeader))
        .headers(headers -> headers.addAll(gatewayHeaders))
        .body(BodyInserters.fromValue(request))
        .retrieve()
        .toEntity(GenericV3Response.class)
        .retryWhen(
            Retry.backoff(5, Duration.ofSeconds(2))
                .filter(
                    throwable ->
                        throwable instanceof HttpServerErrorException
                            || throwable instanceof WebClientRequestException
                            || throwable instanceof ReadTimeoutException
                            || throwable instanceof TimeoutException))
        .block();
  }
}
