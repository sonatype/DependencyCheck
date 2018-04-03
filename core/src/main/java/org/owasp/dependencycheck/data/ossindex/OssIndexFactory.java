package org.owasp.dependencycheck.data.ossindex;

import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.sonatype.ossindex.client.OssIndex;
import org.sonatype.ossindex.client.internal.Urls;
import org.sonatype.ossindex.client.UserAgentProvider;
import org.sonatype.ossindex.client.internal.OssIndexImpl;
import org.sonatype.ossindex.client.internal.OssIndexProvider;
import org.sonatype.ossindex.client.internal.UserAgentProviderImpl;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Produces {@link OssIndex} instances.
 *
 * @since ???
 */
public class OssIndexFactory {
    public static OssIndex create(final Settings settings) {
        String value = settings.getString(Settings.KEYS.ANALYZER_OSSINDEX_URL, OssIndexProvider.DEFAULT_URL);
        if (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        URL baseUrl = Urls.create(value);

        final URLConnectionFactory connectionFactory = new URLConnectionFactory(settings);
        final UserAgentProvider userAgentProvider = new UserAgentProviderImpl(
                "dependency-check",
                settings.getString(Settings.KEYS.APPLICATION_VERSION, "Unknown")
        );

        return new OssIndexImpl(baseUrl, userAgentProvider) {
            @Override
            protected HttpURLConnection connect(final URL url) throws IOException {
                return connectionFactory.createHttpURLConnection(url);
            }
        };
    }
}
