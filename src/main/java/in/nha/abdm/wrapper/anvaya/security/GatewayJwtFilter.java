/* (C) 2026 */
package in.nha.abdm.wrapper.anvaya.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Anvaya (#7): verifies that callbacks on /api/v3/** really come from the ABDM gateway. The gateway
 * sends a signed JWT in the Authorization header; we check its signature against the gateway's
 * public keys (JWKS, cached and refreshed by Nimbus) and its expiry. Upstream accepted any POST.
 */
public class GatewayJwtFilter extends OncePerRequestFilter {

  private static final Logger log = LogManager.getLogger(GatewayJwtFilter.class);

  private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

  public GatewayJwtFilter(String jwksUrl) {
    JWKSource<SecurityContext> keySource;
    try {
      keySource = JWKSourceBuilder.create(new URL(jwksUrl)).retrying(true).build();
    } catch (MalformedURLException e) {
      throw new IllegalStateException("Invalid anvaya.gateway-auth.jwks-url: " + jwksUrl, e);
    }
    DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    processor.setJWSKeySelector(
        new JWSVerificationKeySelector<>(
            Set.of(
                JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.PS256),
            keySource));
    // DefaultJWTProcessor's default claims verifier rejects expired / not-yet-valid tokens.
    this.jwtProcessor = processor;
  }

  /** For tests: plug in a processor with a local key source. */
  GatewayJwtFilter(ConfigurableJWTProcessor<SecurityContext> jwtProcessor) {
    this.jwtProcessor = jwtProcessor;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !RequestPaths.isGatewayCallback(request)
        || "OPTIONS".equalsIgnoreCase(request.getMethod());
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String token = bearerToken(request.getHeader(HttpHeaders.AUTHORIZATION));
    if (token == null) {
      reject(request, response, "missing Authorization header");
      return;
    }
    try {
      jwtProcessor.process(token, null);
    } catch (Exception e) {
      // Do not log the token itself.
      reject(request, response, e.getClass().getSimpleName() + ": " + e.getMessage());
      return;
    }
    chain.doFilter(request, response);
  }

  static String bearerToken(String header) {
    if (header == null || header.isBlank()) {
      return null;
    }
    String h = header.trim();
    if (h.regionMatches(true, 0, "Bearer ", 0, 7)) {
      h = h.substring(7).trim();
    }
    return h.isEmpty() ? null : h;
  }

  private void reject(HttpServletRequest request, HttpServletResponse response, String reason)
      throws IOException {
    log.warn("Rejected gateway callback " + RequestPaths.path(request) + ": " + reason);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType("application/json");
    response.getWriter().write("{\"error\":\"invalid gateway token\"}");
  }
}
