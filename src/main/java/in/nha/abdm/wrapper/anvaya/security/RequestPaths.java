/* (C) 2026 */
package in.nha.abdm.wrapper.anvaya.security;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Anvaya: sorts incoming requests by who is allowed to call them. Anything not matched as a gateway
 * callback or a public path is treated as a facade API and needs an API key (deny by default).
 */
final class RequestPaths {

  /** ABDM gateway callbacks (see v3 GatewayURL). Must carry a gateway-signed JWT. */
  static final String GATEWAY_CALLBACK_PREFIX = "/api/v3/";

  /**
   * HIU data push endpoint (dataPushUrl). Remote HIPs post encrypted bundles here without a gateway
   * token; the payload is protected by Fidelius encryption and the transaction id.
   */
  static final String HIU_DATA_PUSH_PREFIX = "/v3/transfer";

  /** Cloud Run / load balancer health checks. */
  static final String HEALTH_PREFIX = "/actuator/health";

  private RequestPaths() {}

  static String path(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String context = request.getContextPath();
    return (context != null && !context.isEmpty() && uri.startsWith(context))
        ? uri.substring(context.length())
        : uri;
  }

  static boolean isGatewayCallback(HttpServletRequest request) {
    return path(request).startsWith(GATEWAY_CALLBACK_PREFIX);
  }

  static boolean isPublic(HttpServletRequest request) {
    String p = path(request);
    return "OPTIONS".equalsIgnoreCase(request.getMethod())
        || p.startsWith(HIU_DATA_PUSH_PREFIX)
        || p.startsWith(HEALTH_PREFIX);
  }

  static boolean isFacade(HttpServletRequest request) {
    return !isGatewayCallback(request) && !isPublic(request);
  }
}
