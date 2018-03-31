package org.owasp.dependencycheck.data.ossindex;

import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

/**
 * Sonatype OSS Index access.
 *
 * @since ???
 */
public class OssIndex {
    private static final Logger log = LoggerFactory.getLogger(OssIndex.class);

    private static final String DEFAULT_URL = "https://ossindex.sonatype.org";

    private final URL baseUrl;

    private final URLConnectionFactory connectionFactory;

    private final UserAgentProvider userAgent;

    private final PackageReportMarshaller marshaller;

    public OssIndex(final Settings settings) {
        String value = settings.getString(Settings.KEYS.ANALYZER_OSSINDEX_URL, DEFAULT_URL);
        try {
            if (value.endsWith("/")) {
                value = value.substring(0, value.length() - 1);
            }
            baseUrl = new URL(value);
        } catch (MalformedURLException e) {
            throw new RuntimeException(String.format("Invalid setting: %s, value: %s", Settings.KEYS.ANALYZER_OSSINDEX_URL, value), e);
        }
        log.debug("Base URL: {}", baseUrl);

        connectionFactory = new URLConnectionFactory(settings);
        userAgent = new UserAgentProvider(settings);
        marshaller = new PackageReportMarshaller();
    }

    public PackageReport request(final PackageIdentifier id) throws Exception {
        log.debug("Requesting package-report for: {}", id);

        URL url = new URL(String.format("%s/v2.0/package/%s/%s/%s", baseUrl, id.getFormat(), id.getName(), id.getVersion()));
        HttpURLConnection connection = connectionFactory.createHttpURLConnection(url);
        connection.setDoOutput(true);

        // TODO: this could potentially be moved to URLConnectionFactory?
        userAgent.apply(connection);

        connection.addRequestProperty("Accept", "application/json");

        log.debug("Connecting to: {}", url);
        connection.connect();

        // TODO: consider minimal retry logic?

        int status = connection.getResponseCode();
        if (status == HttpURLConnection.HTTP_OK) {
            try (InputStream input = connection.getInputStream()) {
                List<PackageReport> results = marshaller.unmarshal(input);
                // FIXME: sanity, this returns a list but for the endpoint we are using it should only contain a single entry
                return results.get(0);
            }
        }

        throw new RuntimeException("Unexpected response; status: " + status);
    }

    public URL packageUrl(final PackageReport report) {
        String url = String.format("%s/resource/package/%s", baseUrl, report.getId());
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public URL referenceUrl(final PackageReport.Vulnerability vulnerability) {
        String type;
        if (vulnerability.getCve() == null) {
            type = "vulnerability";
        }
        else {
            type = "cve";
        }
        String url = String.format("%s/resource/%s/%s", baseUrl, type, vulnerability.getId());

        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
}
