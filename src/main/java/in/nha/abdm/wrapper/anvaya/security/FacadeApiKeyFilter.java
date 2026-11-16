/* (C) 2026 */
package in.nha.abdm.wrapper.anvaya.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Anvaya (#6): requires {@code X-API-Key} on every facade API (add-patients, link-carecontexts,
 * consent-init, patient lookup, ...). Upstream left these open, and /v3/patient/{id} returns
 * patient demographics.
 */
public class FacadeApiKeyFilter extends OncePerRequestFilter {

  static final String API_KEY_HEADER = "X-API-Key";
  private static final Logger log = LogManager.getLogger(FacadeApiKeyFilter.class);

  private final List<byte[]> validKeys;

  public FacadeApiKeyFilter(String commaSeparatedKeys) {
    this.validKeys =
        Arrays.stream(commaSeparatedKeys == null ? new String[0] : commaSeparatedKeys.split(","))
            .map(String::trim)
            .filter(k -> !k.isEmpty())
            .map(k -> k.getBytes(StandardCharsets.UTF_8))
            .toList();
    if (validKeys.isEmpty()) {
      throw new IllegalStateException(
          "anvaya.facade-auth.enabled=true but no keys are set. Set FACADE_API_KEYS, or set"
              + " FACADE_AUTH_ENABLED=false for local development only.");
    }
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !RequestPaths.isFacade(request);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String presented = request.getHeader(API_KEY_HEADER);
    if (presented != null && matches(presented.getBytes(StandardCharsets.UTF_8))) {
      chain.doFilter(request, response);
      return;
    }
    log.warn(
        "Rejected facade call without a valid API key: "
            + request.getMethod()
            + " "
            + RequestPaths.path(request));
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType("application/json");
    response.getWriter().write("{\"error\":\"missing or invalid X-API-Key\"}");
  }

  private boolean matches(byte[] presented) {
    boolean ok = false;
    // Check every key with a constant-time compare so timing does not reveal which key matched.
    for (byte[] key : validKeys) {
      ok |= MessageDigest.isEqual(key, presented);
    }
    return ok;
  }
}
