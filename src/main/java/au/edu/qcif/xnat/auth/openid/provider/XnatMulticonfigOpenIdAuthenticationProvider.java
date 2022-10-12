/*
 * web: XnatLdapAuthenticationProvider
 * XNAT http://www.xnat.org
 * Copyright (c) 2005-2017, Washington University School of Medicine and Howard Hughes Medical Institute
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package au.edu.qcif.xnat.auth.openid.provider;

import com.google.common.collect.ImmutableList;
import lombok.extern.slf4j.Slf4j;
import org.nrg.xnat.security.provider.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

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
    private final Map<String, ProviderAttributes>               _providerAttributes = new HashMap<>();
    private final Map<String, XnatOpenIdAuthenticationProvider> _providers          = new HashMap<>();

    @Autowired
    public XnatMulticonfigOpenIdAuthenticationProvider(final AuthenticationProviderConfigurationLocator locator) {
        super(locator, OPENID);
    }

    public XnatMulticonfigOpenIdAuthenticationProvider(final Map<String, ProviderAttributes> definitions) {
        super(definitions);
        if (CollectionUtils.isEmpty(definitions)) {
            return;
        }
        new LinkedList<>(definitions.keySet()).stream()
                                              .map(definitions::get)
                                              .forEach(attributes -> Arrays.stream(attributes.getProperty("enabled").split("\\s*,\\s*"))
                                                                           .filter(openIdProviderId -> !_providers.containsKey(openIdProviderId))
                                                                           .forEach(openIdProviderId -> _providers.put(openIdProviderId, new XnatOpenIdAuthenticationProvider(openIdProviderId, attributes))));
    }

    @Override
    protected XnatAuthenticationProvider createAuthenticationProvider(final ProviderAttributes attributes) {
        return new XnatOpenIdAuthenticationProvider(attributes);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getProviderIds() {
        return ImmutableList.copyOf(_providerAttributes.keySet());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<XnatAuthenticationProvider> getProviders() {
        return new ArrayList<>(_providers.values());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public XnatAuthenticationProvider getProvider(final String providerId) {
        return _providers.get(providerId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName(final String providerId) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        return provider != null ? provider.getName() : null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isVisible(final String providerId) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        return provider != null && provider.isVisible();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setVisible(final String providerId, final boolean visible) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        if (provider != null) {
            provider.setVisible(visible);
            _providerAttributes.get(providerId).setVisible(visible);
        }
    }

    @Override
    public String toString() {
        return _providers.values().stream()
                         .map(XnatOpenIdAuthenticationProvider::getName)
                         .collect(Collectors.joining(", "));
    }
}
