package org.owasp.dependencycheck.data.ossindex;

import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.HttpURLConnection;

/**
 * Provides {@code User-Agent} header value.
 *
 * @since ???
 */
public class UserAgentProvider {
    private static final Logger log = LoggerFactory.getLogger(UserAgentProvider.class);

    private String userAgent;

    public UserAgentProvider(final Settings settings) {
        userAgent = String.format("%s/%s (%s; %s; %s; %s)",
                "dependency-check", // Settings.KEYS.APPLICATION_NAME may have been customized and contain spaces
                settings.getString(Settings.KEYS.APPLICATION_VERSION, "Unknown"),
                System.getProperty("os.name"),
                System.getProperty("os.version"),
                System.getProperty("os.arch"),
                System.getProperty("java.version")
        );
        log.debug("User-agent: {}", userAgent);
    }

    public String get() {
        return userAgent;
    }

    public void apply(final HttpURLConnection connection) {
        connection.addRequestProperty("User-Agent", get());
    }
}
