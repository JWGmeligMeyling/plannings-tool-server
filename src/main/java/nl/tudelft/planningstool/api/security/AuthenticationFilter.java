package nl.tudelft.planningstool.api.security;

import javax.annotation.Priority;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

/**
 * Filter applied to requests going to endpoints secured with @Secured.
 * Clients requesting to these endpoints should pass an Authorization HTTP header
 * with "Bearer token" as content, where token is the auth token given to the user.
 */
@Secured
@Provider
@Priority(Priorities.AUTHENTICATION)
public class AuthenticationFilter implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        // Get the HTTP Authorization header from the request
        String authorizationHeader =
                requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);

        // Check if the HTTP Authorization header is present and formatted correctly
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new NotAuthorizedException("Authorization header must be provided");
        }

        // Extract the token from the HTTP Authorization header
        String token = authorizationHeader.substring("Bearer".length()).trim();

        // Validate the token
        validateToken(token);
    }

    private void validateToken(String token) throws NotAuthorizedException{
        if(!token.equals("AAAA-BBBB-CCCC-DDDD")) {
            // Token is invalid for all users.
            // Throw NotAuthorizedException, which passes a 401 HTTP response to the client.
            throw new NotAuthorizedException("Invalid authorization token for this request.");
        }
    }
}

