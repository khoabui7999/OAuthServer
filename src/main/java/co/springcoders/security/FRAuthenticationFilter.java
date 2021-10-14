package co.springcoders.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class FRAuthenticationFilter extends OncePerRequestFilter {
    private final static Logger logger = LoggerFactory.getLogger(FRAuthenticationFilter.class);

    private AuthenticationManager authenticationManager;

    public FRAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Optional<String> token = Optional.ofNullable(request.getHeader("tokenId"));
        try {
            if (token.isPresent()) {
                logger.debug("Trying to authenticate user by tokenId. Token: {}", token);

                PreAuthenticatedAuthenticationToken requestAuthentication = new PreAuthenticatedAuthenticationToken(token, null);

                Authentication authentication = authenticationManager.authenticate(requestAuthentication);
                if (authentication == null || !authentication.isAuthenticated()) {
                    throw new InternalAuthenticationServiceException("Unable to authenticate Domain User for provided credentials");
                }
                logger.debug("User successfully authenticated");

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            logger.debug("AuthenticationFilter is passing request down the filter chain");
            filterChain.doFilter(request, response);
        } catch (InternalAuthenticationServiceException internalAuthenticationServiceException) {
            SecurityContextHolder.clearContext();
            logger.error("Internal authentication service exception", internalAuthenticationServiceException);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (AuthenticationException authenticationException) {
            SecurityContextHolder.clearContext();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authenticationException.getMessage());
        }
    }
}
