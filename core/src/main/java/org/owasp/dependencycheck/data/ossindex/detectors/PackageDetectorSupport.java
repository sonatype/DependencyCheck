package org.owasp.dependencycheck.data.ossindex.detectors;

import org.owasp.dependencycheck.data.ossindex.PackageDetector;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.goodies.packageurl.PackageUrl;

import javax.annotation.Nullable;

/**
 * Support for {@link PackageDetector} implementations.
 *
 * @since ???
 */
public abstract class PackageDetectorSupport implements PackageDetector {
    protected final Logger log = LoggerFactory.getLogger(PackageDetector.class);

    protected final String format;

    protected final String[] ecosystems;

    public PackageDetectorSupport(final String format, final String... ecosystems) {
        this.format = format;
        this.ecosystems = ecosystems;
    }

    @Nullable
    @Override
    public PackageUrl detect(final Dependency dependency) {
        String ecosystem = dependency.getEcosystem();
        for (String accept : this.ecosystems) {
            if (accept.equals(ecosystem)) {
                PackageUrl purl = doDetect(dependency);
                if (purl != null) {
                    return purl;
                }
            }
        }

        return null;
    }

    @Nullable
    protected PackageUrl doDetect(final Dependency dependency) {
        String name = dependency.getName();
        String version = dependency.getVersion();
        if (name != null && version != null) {
            // FIXME: adjust for name vs. namespace
            return new PackageUrl.Builder()
                    .type(format)
                    .name(name)
                    .version(version)
                    .build();
        }
        return null;
    }

    @Nullable
    protected Identifier findIdentifier(final Dependency dependency, final String type) {
        for (Identifier id : dependency.getIdentifiers()) {
            if (type.equals(id.getType())) {
                return id;
            }
        }
        return null;
    }
}
