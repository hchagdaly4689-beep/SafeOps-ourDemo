package ma.ensa.appointmentservice.security;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Set;

public record CurrentUser(String subject, String username, String tenantId, Set<String> roles) {

    public static final String AGENT = "agent";
    public static final String ADMIN = "tenant-admin";

    public boolean hasAnyRole(String... wanted) {
        for (String role : wanted) {
            if (roles.contains(role)) {
                return true;
            }
        }
        return false;
    }

    public void requireStaff() {
        if (!hasAnyRole(AGENT, ADMIN)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "agent or admin role required");
        }
    }
}
