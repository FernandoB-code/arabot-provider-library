package org.arabot.provider.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class UserUtils {

    public String getAutenticatedUserName() {

        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();
        String actualUser = null;

        if (authentication != null) {
            actualUser = authentication.getName();
        }

        return actualUser;
    }

}
