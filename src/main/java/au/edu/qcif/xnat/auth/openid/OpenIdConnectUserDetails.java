/*
 *Copyright (C) 2018 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation; either version 2 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License along
 *with this program; if not, write to the Free Software Foundation, Inc.,
 *51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package au.edu.qcif.xnat.auth.openid;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;

import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.security.XDATUser;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import au.edu.qcif.xnat.auth.openid.helpers.NamedStringFormatter;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.*;
import static org.nrg.xdat.security.helpers.Users.EXPRESSION_USERNAME;

/**
 * OIDC user details
 *
 * @author <a href="https://github.com/shilob">Shilo Banihit</a>
 */
@SuppressWarnings({"ExternalizableWithoutPublicNoArgConstructor", "deprecation"})
@Slf4j
public class OpenIdConnectUserDetails extends XDATUser {
    private static final long    serialVersionUID         = -1568972028866924986L;
    private static final Pattern EXTRACTOR                = Pattern.compile("\\[([a-zA-Z0-9_]+)]");
    private static final String  DEFAULT_USERNAME_PATTERN = "[providerId]_[sub]";

    private       OAuth2AccessToken   token;
    private       String              email;
    private final Map<String, Object> openIdUserInfo;
    private       String              firstName;
    private       String              lastName;
    private       String              username;
    private final String              providerId;
    private final OpenIdAuthPlugin    plugin;

    public OpenIdConnectUserDetails(String providerId, Map<String, Object> userInfo, OAuth2AccessToken token, OpenIdAuthPlugin plugin) {
        this.openIdUserInfo = userInfo;
        this.providerId     = providerId;
        this.setUsername(formatUserName(plugin.getProperty(providerId, USERNAME_PATTERN)));
        this.token  = token;
        this.plugin = plugin;

        this.email = getUserInfo(userInfo, EMAIL);
        this.setFirstname(getUserInfo(userInfo, GIVEN_NAME));
        this.setLastname(getUserInfo(userInfo, FAMILY_NAME));
    }

    public OAuth2AccessToken getToken() {
        return token;
    }

    public void setToken(OAuth2AccessToken token) {
        this.token = token;
    }

    public void setUsername(String username) {
        this.username = sanitizeUsername(username);
    }

    public String getUsername() {
        return username;
    }

    public String getFirstname() {
        return firstName;
    }

    public String getLastname() {
        return lastName;
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String e) {
        this.email = e;
    }

    public void setFirstname(String firstname) {
        this.firstName = firstname;
    }

    public void setLastname(String lastname) {
        this.lastName = lastname;
    }

    private String getUserInfo(final Map<String, Object> userInfo, String propName) {
        String propVal = (String) userInfo.get(plugin.getProperty(providerId, propName));
        return propVal != null ? propVal : "";
    }

    private String formatUserName(final String usernameFormat) {
        // Merge the user information and the plug
        //Map<String, Object> data = new HashMap<>();
        //data.put("provider", this);
        //data.put("user", this.openIdUserInfo);

        this.openIdUserInfo.put("providerId", this.providerId);

        log.debug("Data that can be used is: {}", this.openIdUserInfo);
        log.debug("The username format string is: {}", usernameFormat);

        NamedStringFormatter stringFormatter = new NamedStringFormatter(this.openIdUserInfo);
        String formattedText = stringFormatter.format(usernameFormat);
        log.debug("-> result: {}", formattedText);

        return formattedText;
    }

    /**
     * Sanitizes the username based on the allowed username characters as defined in xdat core. The sanitation method is 
     * to remove the characters that are not in the allowed character specification.
     *
     * @param username The username to sanitize
     *
     * @return Returns the sanitized username
     */
    private static String sanitizeUsername(String username) {
        // The allowed pattern of a username is defined globally in org.nrg.xdat.security.helpers.User.PATTERN_USERNAME
        Pattern allowedPattern = Pattern.compile(EXPRESSION_USERNAME);
        // Create a Matcher object from the global username allowed characters Pattern
        Matcher matcher = allowedPattern.matcher(username);
        
        // Initialize a StringBuilder to store the sanitized username
        StringBuilder sanitizedUsername = new StringBuilder();
        
        log.debug("Sanitizing username: {}", username);
        log.debug("* Using the following pattern for allowed characters: {}", allowedPattern.pattern());
        // Iterate through the input username and append only the allowed characters
        while (matcher.find()) {
            sanitizedUsername.append(matcher.group());
        }
        log.debug("-> result: {}", sanitizedUsername.toString());
        
        // Convert the StringBuilder to a string
        return sanitizedUsername.toString();
    }
}
