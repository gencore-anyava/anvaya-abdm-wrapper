/* (C) 2026 */
package in.nha.abdm.wrapper.anvaya.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/** Anvaya: registers the facade API-key filter (#6) and gateway JWT filter (#7). */
@Configuration
public class AnvayaSecurityConfig {

  private static final Logger log = LogManager.getLogger(AnvayaSecurityConfig.class);

  @Bean
  @ConditionalOnProperty(
      name = "anvaya.facade-auth.enabled",
      havingValue = "true",
      matchIfMissing = true)
  public FilterRegistrationBean<FacadeApiKeyFilter> facadeApiKeyFilter(
      @Value("${anvaya.facade-auth.api-keys:}") String apiKeys) {
    FilterRegistrationBean<FacadeApiKeyFilter> reg =
        new FilterRegistrationBean<>(new FacadeApiKeyFilter(apiKeys));
    reg.addUrlPatterns("/*");
    reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
    return reg;
  }

  @Bean
  @ConditionalOnProperty(
      name = "anvaya.gateway-auth.enabled",
      havingValue = "true",
      matchIfMissing = true)
  public FilterRegistrationBean<GatewayJwtFilter> gatewayJwtFilter(
      @Value("${anvaya.gateway-auth.jwks-url}") String jwksUrl) {
    log.info("Gateway callback JWT verification enabled, keys from " + jwksUrl);
    FilterRegistrationBean<GatewayJwtFilter> reg =
        new FilterRegistrationBean<>(new GatewayJwtFilter(jwksUrl));
    reg.addUrlPatterns("/*");
    reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 11);
    return reg;
  }

  @Bean
  @ConditionalOnProperty(name = "anvaya.gateway-auth.enabled", havingValue = "false")
  public Object gatewayAuthDisabledWarning() {
    log.warn(
        "anvaya.gateway-auth.enabled=false: gateway callbacks are NOT verified."
            + " Use only with the mock gateway.");
    return new Object();
  }
}
