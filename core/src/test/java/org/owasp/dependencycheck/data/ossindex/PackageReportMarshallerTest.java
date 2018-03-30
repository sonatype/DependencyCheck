package org.owasp.dependencycheck.data.ossindex;

import org.junit.Before;
import org.junit.Test;

import java.io.InputStream;
import java.net.URL;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

/**
 * Tests for {@link PackageReportMarshaller}.
 */
public class PackageReportMarshallerTest {
    private PackageReportMarshaller underTest;

    @Before
    public void setUp() throws Exception {
        underTest = new PackageReportMarshaller();
    }

    @Test
    public void maven_nomatch() throws Exception {
        URL resource = getClass().getResource("maven-no-such-package-0.txt");
        try (InputStream input = resource.openStream()) {
            List<PackageReport> result = underTest.unmarshal(input);
            assertThat(result.size(), is(1));

            PackageReport report = result.get(0);
            assertThat(report, notNullValue(PackageReport.class));
            assertThat(report.getId(), is(0L));
            assertThat(report.getFormat(), is("maven"));
            assertThat(report.getName(), is("no-such-package"));
            assertThat(report.getVersion(), is("0"));
            assertThat(report.getVulnerabilityTotal(), is(0));
            assertThat(report.getVulnerabilityMatches(), is(0));
        }
    }

    @Test
    public void nuget_jquery_match() throws Exception {
        URL resource = getClass().getResource("nuget-jquery-1.9.0.txt");
        try (InputStream input = resource.openStream()) {
            List<PackageReport> result = underTest.unmarshal(input);
            assertThat(result.size(), is(1));

            PackageReport report = result.get(0);
            assertThat(report, notNullValue(PackageReport.class));
            assertThat(report.getId(), is(8396450687L));
            assertThat(report.getFormat(), is("nuget"));
            assertThat(report.getName(), is("jQuery"));
            assertThat(report.getVersion(), is("1.9.0"));
            assertThat(report.getVulnerabilityTotal(), is(7));
            assertThat(report.getVulnerabilityMatches(), is(2));

            List<PackageReport.Vulnerability> vulnerabilities = report.getVulnerabilities();
            assertThat(vulnerabilities.size(), is(2));

            PackageReport.Vulnerability vuln1 = vulnerabilities.get(0);
            assertThat(vuln1, notNullValue(PackageReport.Vulnerability.class));
            assertThat(vuln1.getId(), is(8399962417L));
            assertThat(vuln1.getResource(), is("https://github.com/jquery/jquery/issues/2432"));
            assertThat(vuln1.getTitle(), is("Cross Site Scripting (XSS)"));
            assertThat(vuln1.getVersions(), notNullValue());
            assertThat(vuln1.getVersions().size(), is(1));
            assertThat(vuln1.getReferences(), notNullValue());
            assertThat(vuln1.getReferences().size(), is(5));
            assertThat(vuln1.getPublished(), is(1470469775500L));
            assertThat(vuln1.getUpdated(), is(1490153875967L));
        }
    }
}
