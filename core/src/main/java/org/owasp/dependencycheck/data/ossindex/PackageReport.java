package org.owasp.dependencycheck.data.ossindex;

import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

// NOTE: this is based on the current v2 REST api, but likely to change

/**
 * Package report information gathered from Sonatype OSS Index.
 *
 * @since ???
 *
 * @see PackageReportMarshaller
 */
public class PackageReport {
    private long id;

    @SerializedName("pm")
    private String format;

    private String name;

    private String version;

    @SerializedName("vulnerability-total")
    private int vulnerabilityTotal;

    @SerializedName("vulnerability-matches")
    private int vulnerabilityMatches;

    public static class Vulnerability
    {
        private long id;

        private String resource;

        private String title;

        private String description;

        private List<String> versions = new ArrayList<>();

        private List<String> references = new ArrayList<>();

        private long published;

        private long updated;

        private String cve;

        public long getId() {
            return id;
        }

        public void setId(long id) {
            this.id = id;
        }

        public String getResource() {
            return resource;
        }

        public void setResource(String resource) {
            this.resource = resource;
        }

        public String getTitle() {
            return title;
        }

        public void setTitle(String title) {
            this.title = title;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public List<String> getVersions() {
            return versions;
        }

        public void setVersions(List<String> versions) {
            this.versions = versions;
        }

        public List<String> getReferences() {
            return references;
        }

        public void setReferences(List<String> references) {
            this.references = references;
        }

        public long getPublished() {
            return published;
        }

        public void setPublished(long published) {
            this.published = published;
        }

        public long getUpdated() {
            return updated;
        }

        public void setUpdated(long updated) {
            this.updated = updated;
        }

        public String getCve() {
            return cve;
        }

        public void setCve(String cve) {
            this.cve = cve;
        }
    }

    private List<Vulnerability> vulnerabilities = new ArrayList<>();

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public int getVulnerabilityTotal() {
        return vulnerabilityTotal;
    }

    public void setVulnerabilityTotal(int vulnerabilityTotal) {
        this.vulnerabilityTotal = vulnerabilityTotal;
    }

    public int getVulnerabilityMatches() {
        return vulnerabilityMatches;
    }

    public void setVulnerabilityMatches(int vulnerabilityMatches) {
        this.vulnerabilityMatches = vulnerabilityMatches;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }
}
