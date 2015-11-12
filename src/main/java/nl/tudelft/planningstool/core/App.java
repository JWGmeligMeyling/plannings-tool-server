package nl.tudelft.planningstool.core;

import com.google.inject.Injector;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
//import nl.tudelft.planningstool.core.saml.SAMLAuthenticator;
//import nl.tudelft.planningstool.core.saml.SAMLLoginService;
import org.eclipse.jetty.security.*;
import org.eclipse.jetty.security.authentication.FormAuthenticator;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.security.authentication.BasicAuthenticator;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.session.HashSessionIdManager;
import org.eclipse.jetty.util.security.Credential;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class App {

    public static final int PORT = 9000;
    final Server server;

    @Getter
    private final AtomicReference<Injector> injectorAtomicReference = new AtomicReference<>();

    public App() {
        this.server = new Server(PORT);
        this.server.setSessionIdManager(new HashSessionIdManager());
        this.server.setHandler(this.attachHandlers());
    }

    private SecurityHandler basicAuth() {

        HashLoginService l = new HashLoginService();
        l.putUser("sjaars", Credential.getCredential("slapwachtwoord"), new String[]{"student"});
        l.putUser("gijs", Credential.getCredential("superduperwachtwoord"), new String[]{"student", "teacher"});
        l.setName("planningstool");

//        SAMLLoginService saml = new SAMLLoginService();
//        saml.setName("SamlLogin");

        // Create constraint to
        Constraint constraint = new Constraint();
        constraint.setName(Constraint.__BASIC_AUTH);
        constraint.setRoles(new String[]{"student"});
        constraint.setAuthenticate(true);

        ConstraintMapping cm = new ConstraintMapping();
        cm.setConstraint(constraint);
        cm.setPathSpec("/*");


        Constraint constraint2 = new Constraint();
        constraint2.setName(Constraint.__BASIC_AUTH);
        constraint2.setRoles(new String[]{"teacher"});
        constraint2.setAuthenticate(true);

        ConstraintMapping cmAdmin = new ConstraintMapping();
        cmAdmin.setConstraint(constraint2);
        cmAdmin.setPathSpec("/v1/users/USER-aba62cd5-caa6-4e42-a5d6-4909f03038bf/courses/*");

        ConstraintSecurityHandler csh = new ConstraintSecurityHandler();
        csh.setAuthenticator(new BasicAuthenticator());
        //csh.setAuthenticator(new SAMLAuthenticator());
        csh.setRealmName("planningstool");
        csh.addConstraintMapping(cm);
        csh.addConstraintMapping(cmAdmin);
        csh.setLoginService(l);
        //csh.setLoginService(saml);

        return csh;
    }

    private ContextHandlerCollection attachHandlers() {
        final RequestHandler requestHandler = new RequestHandler(this);
        requestHandler.setSecurityHandler(basicAuth());

        final ContextHandlerCollection handlers = new ContextHandlerCollection();
        handlers.addContext("/", "/").setHandler(requestHandler);
        return handlers;
    }

    /**
     * Starts the {@link App} server.
     *
     * @throws Exception
     *             In case the server could not be started.
     */
    public void startServer() throws Exception {
        this.server.start();
        Runtime.getRuntime().addShutdownHook(new Thread(this::stopServer));
    }

    /**
     * Joins the {@link App} server.
     *
     * @throws InterruptedException
     *             if the joined thread is interrupted
     *             before or during the merging.
     */
    public void joinThread() throws InterruptedException {
        this.server.join();
    }

    /**
     * Stops the {@link App} server.
     */
    public void stopServer() {
        try {
            this.server.stop();
        } catch (final Exception e) {
            log.warn(e.getMessage(), e);
        }
    }

    public static void main(String... args) throws Exception {
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();

        final App app = new App();
        app.startServer();
        app.joinThread();
    }
}
