package nl.tudelft.planningstool.api.v1;


import nl.tudelft.planningstool.api.parameters.Credentials;
import nl.tudelft.planningstool.api.responses.TokenResponse;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;


/**
 * Provides Authentication API endpoints.
 */
@Path("v1/authentication")
public class AuthenticationAPI {

    @POST
    @Produces("application/json")
    @Consumes("application/json")
    public Response authenticateUser(Credentials credentials) {
        String username = credentials.getUsername();
        String password = credentials.getPassword();

        // Authenticate the user, issue a token and return a response
        try {
            authenticate(username, password);

            TokenResponse token = issueToken(username);

            return Response.ok(token).build();
        }
        catch (Exception e) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
    }

    private TokenResponse issueToken(String username) {
        TokenResponse response = new TokenResponse();
        long oneDayFromNow = System.currentTimeMillis() + 86_400_000;
        String token = generateToken(username);

        response.setToken(token);
        response.setEndOfValidity(oneDayFromNow);

        // FIXME: Store token and validity in User table

        return response;
    }

    private String generateToken(String username) {
        return "AAAA-BBBB-CCCC-DDDD"; //FIXME
    }

    private void authenticate(String username, String password) {
        // FIXME: Check database for username/password combination.
        // Throw exception if auth is invalid
        return;
    }

}
