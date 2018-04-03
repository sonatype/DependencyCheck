package org.owasp.dependencycheck.data.ossindex;

import com.google.common.net.HttpHeaders;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.sonatype.ossindex.client.OssIndex;
import org.sonatype.ossindex.client.internal.*;
import org.sonatype.ossindex.client.transport.HttpUrlConnectionTransport;
import org.sonatype.ossindex.client.transport.Transport;
import org.sonatype.ossindex.client.transport.UserAgentProvider;

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
        final UserAgentProvider userAgentProvider = new UserAgentProvider(
                "dependency-check",
                settings.getString(Settings.KEYS.APPLICATION_VERSION, "Unknown")
        );

        Transport transport = new HttpUrlConnectionTransport()
        {
            @Override
            protected HttpURLConnection connect(final URL url) throws IOException {
                HttpURLConnection connection = connectionFactory.createHttpURLConnection(url);
                connection.setRequestProperty(HttpHeaders.USER_AGENT, userAgentProvider.get());
                return connection;
            }
        };

        return new OssIndexImpl(baseUrl, transport);
    }
}
