package org.owasp.dependencycheck.data.ossindex;

import org.sonatype.ossindex.service.client.OssindexClient;
import org.sonatype.ossindex.service.client.OssindexClientConfiguration;
import org.sonatype.ossindex.service.client.internal.GsonMarshaller;
import org.sonatype.ossindex.service.client.internal.OssindexClientImpl;
import org.sonatype.ossindex.service.client.transport.HttpUrlConnectionTransport;
import org.sonatype.ossindex.service.client.transport.Marshaller;
import org.sonatype.ossindex.service.client.transport.Transport;
import org.sonatype.ossindex.service.client.transport.UserAgentSupplier;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Produces {@link OssindexClient} instances.
 *
 * @since ???
 */
public class OssindexClientFactory {
    public static OssindexClient create(final Settings settings) {
        OssindexClientConfiguration config = new OssindexClientConfiguration();

        String baseUrl = settings.getString(Settings.KEYS.ANALYZER_OSSINDEX_URL, null);
        if (baseUrl != null) {
            config.setBaseUrl(baseUrl);
        }

        // customize User-Agent for use with dependency-check
        final UserAgentSupplier userAgent = new UserAgentSupplier(
                "dependency-check",
                settings.getString(Settings.KEYS.APPLICATION_VERSION, "unknown")
        );

        Transport transport = new HttpUrlConnectionTransport(userAgent)
        {
            final URLConnectionFactory connectionFactory = new URLConnectionFactory(settings);

            @Override
            protected HttpURLConnection connect(final URL url) throws IOException {
                HttpURLConnection connection = connectionFactory.createHttpURLConnection(url);
                connection.setRequestProperty("User-Agent", userAgent.get());

                // TODO: optionally configure authentication

                return connection;
            }
        };

        Marshaller marshaller = new GsonMarshaller();

        return new OssindexClientImpl(config, transport, marshaller);
    }
}
