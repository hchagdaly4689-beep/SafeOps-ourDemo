package ma.ensa.apigateway.auth;

import ma.ensa.apigateway.auth.util.Jwt;
import ma.ensa.apigateway.auth.util.JwtHeader;
import ma.ensa.apigateway.auth.util.JwtPayload;
import ma.ensa.apigateway.auth.util.RealmAccess;
import ma.ensa.apigateway.auth.web.AuthenticatedRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuthenticatedIdentityTest {

    @Test
    void forgedTenantHeaderIsIgnored() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Auth-Tenant", "tenant-b");

        AuthenticatedRequest forwarded = new AuthenticatedRequest(
                request, user("tenant-a", Set.of("agent")));

        assertEquals("tenant-a", forwarded.getHeader(AuthenticatedRequest.TENANT));
        assertEquals(List.of("tenant-a"), Collections.list(forwarded.getHeaders(AuthenticatedRequest.TENANT)));
    }

    @Test
    void staffTokenCarriesTenantId() {
        assertEquals("tenant-a", AuthenticatedUser.from(token("tenant-a", Set.of("agent"))).tenantId());
    }

    @Test
    void globalClientTokenHasNoTenantId() {
        assertNull(AuthenticatedUser.from(token(null, Set.of("client"))).tenantId());
    }

    @Test
    void providerAdminTokenHasNoTenantId() {
        assertNull(AuthenticatedUser.from(token(null, Set.of("provider-admin"))).tenantId());
    }

    private static AuthenticatedUser user(String tenantId, Set<String> roles) {
        return AuthenticatedUser.from(token(tenantId, roles));
    }

    private static Jwt token(String tenantId, Set<String> roles) {
        JwtPayload payload = new JwtPayload(
                "subject", "http://keycloak/realms/tiko", 1L, 1L, null,
                "jti", "Bearer", "frontend", null, "openid",
                Set.of("tiko-api"), "Test User", "test-user", "test@tiko.test",
                tenantId, new RealmAccess(roles), Map.of());
        return new Jwt(new JwtHeader("RS256", "JWT", "test"), payload, new byte[0], "signed");
    }
}
