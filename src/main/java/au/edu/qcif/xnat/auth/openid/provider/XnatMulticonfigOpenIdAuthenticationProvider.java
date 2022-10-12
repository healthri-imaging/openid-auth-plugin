/*
 * web: XnatLdapAuthenticationProvider
 * XNAT http://www.xnat.org
 * Copyright (c) 2005-2017, Washington University School of Medicine and Howard Hughes Medical Institute
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package au.edu.qcif.xnat.auth.openid.provider;

import lombok.extern.slf4j.Slf4j;
import org.nrg.xnat.security.provider.AbstractBaseXnatMulticonfigAuthenticationProvider;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.nrg.xnat.security.provider.XnatAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Map;

import static org.nrg.xdat.services.XdatUserAuthService.OPENID;

/**
 * This class represents both an individual XNAT provider and, in the case where multiple LDAP configurations are
 * provided for a single deployment, an aggregator of XNAT providers. This is a dummy provider to properly process
 * the AuthenticationEventPublisher:publishAuthenticationSuccess handler method and the actual authentication is
 * performed on the OpenIdConnectFilter class.
 */
@Component
@Slf4j
public class XnatMulticonfigOpenIdAuthenticationProvider extends AbstractBaseXnatMulticonfigAuthenticationProvider {
    @Autowired
    public XnatMulticonfigOpenIdAuthenticationProvider(final AuthenticationProviderConfigurationLocator locator) {
        super(locator, OPENID);
    }

    public XnatMulticonfigOpenIdAuthenticationProvider(final Map<String, ProviderAttributes> definitions) {
        super(definitions);
    }

    @Override
    protected XnatAuthenticationProvider createAuthenticationProvider(final ProviderAttributes attributes) {
        return new XnatOpenIdAuthenticationProvider(attributes);
    }
}
