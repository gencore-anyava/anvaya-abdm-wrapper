/* (C) 2026 */
package in.nha.abdm.wrapper.anvaya.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.util.Date;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class AnvayaSecurityFiltersTest {

  private static RSAKey gatewayKey;
  private static RSAKey otherKey;
  private static GatewayJwtFilter gatewayFilter;

  @BeforeAll
  static void setUp() throws Exception {
    gatewayKey = new RSAKeyGenerator(2048).keyID("gw").generate();
    otherKey = new RSAKeyGenerator(2048).keyID("gw").generate();
    DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    processor.setJWSKeySelector(
        new JWSVerificationKeySelector<>(
            JWSAlgorithm.RS256, new ImmutableJWKSet<>(new JWKSet(gatewayKey.toPublicJWK()))));
    gatewayFilter = new GatewayJwtFilter(processor);
  }

  private static String token(RSAKey key, Date expiry) throws Exception {
    SignedJWT jwt =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
            new JWTClaimsSet.Builder().subject("gateway").expirationTime(expiry).build());
    jwt.sign(new RSASSASigner(key));
    return jwt.serialize();
  }

  private static int run(
      jakarta.servlet.Filter filter, String method, String path, String header, String value)
      throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest(method, path);
    if (header != null) {
      req.addHeader(header, value);
    }
    MockHttpServletResponse res = new MockHttpServletResponse();
    MockFilterChain chain = new MockFilterChain();
    filter.doFilter(req, res, chain);
    return chain.getRequest() != null ? 200 : res.getStatus();
  }

  // ---------- #6 facade API key ----------

  @Test
  void facadeRequiresValidKey() throws Exception {
    FacadeApiKeyFilter f = new FacadeApiKeyFilter("old-key, new-key");
    assertEquals(401, run(f, "GET", "/v3/patient/123", null, null));
    assertEquals(401, run(f, "PUT", "/v3/add-patients", "X-API-Key", "wrong"));
    assertEquals(200, run(f, "PUT", "/v3/add-patients", "X-API-Key", "new-key"));
    assertEquals(200, run(f, "POST", "/v3/consent-init", "X-API-Key", "old-key"));
  }

  @Test
  void facadeFilterSkipsCallbacksDataPushHealthAndPreflight() throws Exception {
    FacadeApiKeyFilter f = new FacadeApiKeyFilter("k");
    assertEquals(200, run(f, "POST", "/api/v3/hip/patient/care-context/discover", null, null));
    assertEquals(200, run(f, "POST", "/v3/transfer/", null, null));
    assertEquals(200, run(f, "GET", "/actuator/health", null, null));
    assertEquals(200, run(f, "OPTIONS", "/v3/add-patients", null, null));
  }

  @Test
  void facadeFilterRefusesToStartWithoutKeys() {
    assertThrows(IllegalStateException.class, () -> new FacadeApiKeyFilter(" , "));
    assertThrows(IllegalStateException.class, () -> new FacadeApiKeyFilter(null));
  }

  // ---------- #7 gateway JWT ----------

  @Test
  void gatewayCallbackAcceptsValidSignedToken() throws Exception {
    String t = token(gatewayKey, new Date(System.currentTimeMillis() + 60_000));
    assertEquals(
        200,
        run(gatewayFilter, "POST", "/api/v3/consent/request/hip/notify", "Authorization",
            "Bearer " + t));
  }

  @Test
  void gatewayCallbackRejectsMissingForgedOrExpiredToken() throws Exception {
    String path = "/api/v3/hip/health-information/request";
    assertEquals(401, run(gatewayFilter, "POST", path, null, null));
    String forged = token(otherKey, new Date(System.currentTimeMillis() + 60_000));
    assertEquals(401, run(gatewayFilter, "POST", path, "Authorization", "Bearer " + forged));
    String expired = token(gatewayKey, new Date(System.currentTimeMillis() - 600_000));
    assertEquals(401, run(gatewayFilter, "POST", path, "Authorization", "Bearer " + expired));
    assertEquals(401, run(gatewayFilter, "POST", path, "Authorization", "Bearer not-a-jwt"));
  }

  @Test
  void gatewayFilterIgnoresFacadePaths() throws Exception {
    assertEquals(200, run(gatewayFilter, "PUT", "/v3/add-patients", null, null));
  }

  @Test
  void bearerParsing() {
    assertNull(GatewayJwtFilter.bearerToken(null));
    assertNull(GatewayJwtFilter.bearerToken("Bearer "));
    assertEquals("abc", GatewayJwtFilter.bearerToken("bearer abc"));
    assertNotNull(GatewayJwtFilter.bearerToken("abc"));
  }
}
