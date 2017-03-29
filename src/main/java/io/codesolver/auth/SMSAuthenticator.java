package io.codesolver.auth;

import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.descriptor.web.LoginConfig;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;

public class SMSAuthenticator extends FormAuthenticator {

    private static final Log log = LogFactory.getLog(SMSAuthenticator.class);

    private static final String FORM_CODE = "j_code";
    /**
     * Authenticate the user making this request, based on the specified
     * login configuration.  Return <code>true</code> if any specified
     * constraint has been satisfied, or <code>false</code> if we have
     * created a response challenge already.
     *
     * @param request Request we are processing
     * @param response Response we are creating
     *
     * @exception IOException if an input/output error occurs
     */
    @Override
    protected boolean doAuthenticate(Request request, HttpServletResponse response)
            throws IOException {

        if (checkForCachedAuthentication(request, response, true)) {
            return true;
        }

        // References to objects we will need later
        Session session = null;
        Principal principal = null;

        // Have we authenticated this user before but have caching disabled?
        if (!cache) {
            throw new IllegalStateException("Principal cache disabled!");
        }

        // Is this the re-submit of the original request URI after successful
        // authentication?  If so, forward the *original* request instead.
        if (matchRequest(request)) {
            session = request.getSessionInternal(true);
            if (log.isDebugEnabled()) {
                log.debug("Restore request from session '"
                        + session.getIdInternal()
                        + "'");
            }
            principal = (Principal)
                    session.getNote(Constants.FORM_PRINCIPAL_NOTE);
            register(request, response, principal, HttpServletRequest.FORM_AUTH,
                    (String) session.getNote(Constants.SESS_USERNAME_NOTE),
                    (String) session.getNote(Constants.SESS_PASSWORD_NOTE));
            // If we're caching principals we no longer need the username
            // and password in the session, so remove them
            if (cache) {
                session.removeNote(Constants.SESS_USERNAME_NOTE);
                session.removeNote(Constants.SESS_PASSWORD_NOTE);
            }
            if (restoreRequest(request, session)) {
                if (log.isDebugEnabled()) {
                    log.debug("Proceed to restored request");
                }
                return true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Restore of original request failed");
                }
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return false;
            }
        }

        // Acquire references to objects we will need to evaluate
        String contextPath = request.getContextPath();
        String requestURI = request.getDecodedRequestURI();

        // Is this the action request from the login page?
        boolean loginAction =
                requestURI.startsWith(contextPath) &&
                        requestURI.endsWith(Constants.FORM_ACTION);

        LoginConfig config = context.getLoginConfig();

        // No -- Save this request and redirect to the form login page
        if (!loginAction) {
            // If this request was to the root of the context without a trailing
            // '/', need to redirect to add it else the submit of the login form
            // may not go to the correct web application
            if (request.getServletPath().length() == 0 && request.getPathInfo() == null) {
                StringBuilder location = new StringBuilder(requestURI);
                location.append('/');
                if (request.getQueryString() != null) {
                    location.append('?');
                    location.append(request.getQueryString());
                }
                response.sendRedirect(response.encodeRedirectURL(location.toString()));
                return false;
            }

            session = request.getSessionInternal(true);
            if (log.isDebugEnabled()) {
                log.debug("Save request in session '" + session.getIdInternal() + "'");
            }
            try {
                saveRequest(request, session);
            } catch (IOException ioe) {
                log.debug("Request body too big to save during authentication");
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        sm.getString("authenticator.requestBodyTooBig"));
                return false;
            }
            forwardToLoginPage(request, response, config);
            return false;
        }

        // Yes -- Acknowledge the request, validate the specified credentials
        // and redirect to the error page if they are not correct
        request.getResponse().sendAcknowledgement();
        Realm realm = context.getRealm();
        if (!(realm instanceof SMSRealm)) {
            throw new IllegalStateException("Wrong realm class.");
        }
        SMSRealm smsRealm = (SMSRealm)realm;
        if (characterEncoding != null) {
            request.setCharacterEncoding(characterEncoding);
        }
        String username = request.getParameter(Constants.FORM_USERNAME);
        String password = request.getParameter(Constants.FORM_PASSWORD);
        String code = request.getParameter(FORM_CODE);
        if (log.isDebugEnabled()) {
            log.debug("Authenticating username '" + username + "'");
        }
        principal = smsRealm.authenticate(username, password, code);
        if (principal == null) {
            forwardToErrorPage(request, response, config);
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Authentication of '" + username + "' was successful");
        }

        if (session == null) {
            session = request.getSessionInternal(false);
        }
        if (session == null) {
            if (containerLog.isDebugEnabled()) {
                containerLog.debug
                        ("User took so long to log on the session expired");
            }
            if (landingPage == null) {
                response.sendError(HttpServletResponse.SC_REQUEST_TIMEOUT,
                        sm.getString("authenticator.sessionExpired"));
            } else {
                // Make the authenticator think the user originally requested
                // the landing page
                String uri = request.getContextPath() + landingPage;
                SavedRequest saved = new SavedRequest();
                saved.setMethod("GET");
                saved.setRequestURI(uri);
                saved.setDecodedRequestURI(uri);
                request.getSessionInternal(true).setNote(
                        Constants.FORM_REQUEST_NOTE, saved);
                response.sendRedirect(response.encodeRedirectURL(uri));
            }
            return false;
        }

        // Save the authenticated Principal in our session
        session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);

        // Save the username and password as well
        session.setNote(Constants.SESS_USERNAME_NOTE, username);
        session.setNote(Constants.SESS_PASSWORD_NOTE, password);

        // Redirect the user to the original request URI (which will cause
        // the original request to be restored)
        requestURI = savedRequestURL(session);
        if (log.isDebugEnabled()) {
            log.debug("Redirecting to original '" + requestURI + "'");
        }
        if (requestURI == null) {
            if (landingPage == null) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        sm.getString("authenticator.formlogin"));
            } else {
                // Make the authenticator think the user originally requested
                // the landing page
                String uri = request.getContextPath() + landingPage;
                SavedRequest saved = new SavedRequest();
                saved.setMethod("GET");
                saved.setRequestURI(uri);
                saved.setDecodedRequestURI(uri);
                session.setNote(Constants.FORM_REQUEST_NOTE, saved);
                response.sendRedirect(response.encodeRedirectURL(uri));
            }
        } else {
            // Until the Servlet API allows specifying the type of redirect to
            // use.
            Response internalResponse = request.getResponse();
            String location = response.encodeRedirectURL(requestURI);
            if ("HTTP/1.1".equals(request.getProtocol())) {
                internalResponse.sendRedirect(location,
                        HttpServletResponse.SC_SEE_OTHER);
            } else {
                internalResponse.sendRedirect(location,
                        HttpServletResponse.SC_FOUND);
            }
        }
        return false;

    }
}
