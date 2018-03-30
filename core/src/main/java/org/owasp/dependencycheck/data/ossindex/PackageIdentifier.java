package org.owasp.dependencycheck.data.ossindex;

import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Identifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sonatype OSS Index package identifier.
 *
 * @since ???
 */
public class PackageIdentifier {
    private static final Logger log = LoggerFactory.getLogger(PackageIdentifier.class);

    public static final String TYPE = "ossindex";

    private final String format;

    // TODO: consider adding namespace for purl-ish parity?

    private final String name;

    private final String version;

    private final Confidence confidence;

    public PackageIdentifier(final String format, final String name, final String version) {
        this.format = format;
        this.name = name;
        this.version = version;

        // detection may not be able to fully detect distinct name and version, adjust confidence if they overlap
        if (name.contains(version) || version.contains(name)) {
            confidence = Confidence.MEDIUM;
        }
        else {
            confidence = Confidence.HIGH;
        }
    }

    public PackageIdentifier(final String format, final String name, final String version, final Confidence confidence) {
        this.format = format;
        this.name = name;
        this.version = version;
        this.confidence = confidence;
    }

    public String getFormat() {
        return format;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public Confidence getConfidence() {
        return confidence;
    }

    @Override
    public boolean equals(final Object value) {
        if (this == value) return true;
        if (value == null || getClass() != value.getClass()) return false;
        PackageIdentifier that = (PackageIdentifier) value;
        return Objects.equals(format, that.format) &&
                Objects.equals(name, that.name) &&
                Objects.equals(version, that.version) &&
                confidence == that.confidence;
    }

    @Override
    public int hashCode() {
        return Objects.hash(format, name, version, confidence);
    }

    /**
     * Returns PURL-ish string representation as: "{@code <format>:<name>@<version>}".
     *
     * @see #parse(String)
     */
    public String getValue() {
        return String.format("%s:%s@%s", format, name, version);
    }

    @Override
    public String toString() {
        return String.format("%s (%s)", getValue(), confidence);
    }

    public Identifier asIdentifier() {
        Identifier id = new Identifier(TYPE, getValue(), null);
        id.setConfidence(confidence);
        return id;
    }

    private static final Pattern PATTERN = Pattern.compile("(?<format>.+):(?<name>.+)@(?<version>.+)");

    public static PackageIdentifier parse(final String value) {
        Matcher m = PATTERN.matcher(value);
        if (m.matches()) {
            String format = m.group("format");
            String name = m.group("name");
            String version = m.group("version");
            return new PackageIdentifier(format, name, version);
        }
        throw new RuntimeException("Invalid package-identifier: " + value);
    }
}
