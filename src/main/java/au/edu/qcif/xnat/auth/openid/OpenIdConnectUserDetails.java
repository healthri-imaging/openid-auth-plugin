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

import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.security.XDATUser;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.*;

/**
 * OIDC user details
 *
 * @author <a href="https://github.com/shilob">Shilo Banihit</a>
 */
@SuppressWarnings({"ExternalizableWithoutPublicNoArgConstructor", "deprecation"})
public class OpenIdConnectUserDetails extends XDATUser {
    private static final long    serialVersionUID         = -1568972028866924986L;
    private static final Pattern EXTRACTOR                = Pattern.compile("\\[([a-zA-Z0-9_]+)]");
    private static final String  DEFAULT_USERNAME_PATTERN = "[providerId]_[sub]";

    private       OAuth2AccessToken   token;
    private       String              email;
    private final Map<String, String> openIdUserInfo;
    private       String              firstName;
    private       String              lastName;
    private       String              username;
    private final String              providerId;
    private final OpenIdAuthPlugin    plugin;

    public OpenIdConnectUserDetails(String providerId, Map<String, String> userInfo, OAuth2AccessToken token, OpenIdAuthPlugin plugin) {
        this.openIdUserInfo = userInfo;
        this.providerId     = providerId;
        this.setUsername(resolvePattern(plugin.getProperty(providerId, USERNAME_PATTERN)));
        this.token  = token;
        this.plugin = plugin;

        this.email = getUserInfo(userInfo, EMAIL);
        this.setFirstname(getUserInfo(userInfo, GIVEN_NAME));
        this.setLastname(getUserInfo(userInfo, FAMILY_NAME));
    }

    public String getFieldValue(String fieldName) {
        String value = null;
        try {
            Field field = this.getClass().getDeclaredField(fieldName);
            value = (String) field.get(this);
        } catch (Exception e) {
            if (openIdUserInfo != null) {
                value = openIdUserInfo.get(fieldName);
            }
        }
        return value;
    }

    public OAuth2AccessToken getToken() {
        return token;
    }

    public void setToken(OAuth2AccessToken token) {
        this.token = token;
    }

    public void setUsername(String username) {
        this.username = username;
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

    private String getUserInfo(final Map<String, String> userInfo, String propName) {
        String propVal = userInfo.get(plugin.getProperty(providerId, propName));
        return propVal != null ? propVal : "";
    }

    private String resolvePattern(final String usernamePattern) {
        final String  pattern = StringUtils.defaultIfBlank(usernamePattern, DEFAULT_USERNAME_PATTERN);
        final Matcher matcher = EXTRACTOR.matcher(pattern);

        HashMap<String, String> pairs = new HashMap<>();

        final AtomicInteger index = new AtomicInteger();
        while (matcher.find(index.get())) {
            pairs.put(matcher.group(0), matcher.group(1));
            index.set(matcher.end());
        }

        String converted = pattern;
        for (final String key : pairs.keySet()) {
            converted = converted.replace(key, getFieldValue(pairs.get(key)));
        }
        return converted;
    }
}
