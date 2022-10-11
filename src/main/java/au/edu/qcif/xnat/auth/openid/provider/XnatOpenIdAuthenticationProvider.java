package au.edu.qcif.xnat.auth.openid.provider;

import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthRequestToken;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.security.provider.AbstractBaseXnatAuthenticationProvider;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.nrg.xnat.security.tokens.XnatAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@Getter
@Setter
@Accessors(prefix = "_")
@Slf4j
public class XnatOpenIdAuthenticationProvider extends AbstractBaseXnatAuthenticationProvider {
    public XnatOpenIdAuthenticationProvider(final ProviderAttributes attributes) {
        super(attributes);
    }

    public XnatOpenIdAuthenticationProvider(final String providerId, final ProviderAttributes attributes) {
        super(providerId, attributes);
    }

    @Override
    public String getAuthMethod() {
        return XdatUserAuthService.OPENID;
    }

    @Override
    public boolean isVisible() {
        return false;
    }

    @Override
    public void setVisible(final boolean visible) {
        log.info("Can't set OpenID providers to visible");
    }

    @Override
    public XnatAuthenticationToken createToken(final String username, final String password) {
        return new OpenIdAuthRequestToken(username, getProviderId());
    }

    @Override
    public boolean supports(final Authentication authentication) {
        return supports(authentication.getClass()) &&
               authentication instanceof OpenIdAuthRequestToken &&
               StringUtils.equals(getProviderId(), ((OpenIdAuthRequestToken) authentication).getProviderId());
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("This is the dummy provider");
        return null;
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return false;
    }
}
