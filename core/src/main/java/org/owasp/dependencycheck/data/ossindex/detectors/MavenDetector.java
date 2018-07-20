package org.owasp.dependencycheck.data.ossindex.detectors;

import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.data.ossindex.EvidenceExtractor;
import org.owasp.dependencycheck.data.ossindex.PackageDetector;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Identifier;
import org.sonatype.goodies.packageurl.PackageUrl;

import javax.annotation.Nullable;

/**
 * Maven (Java) {@link PackageDetector}.
 *
 * @since ???
 */
public class MavenDetector extends PackageDetectorSupport {
    public static final String FORMAT = "maven";

    public MavenDetector() {
        super(FORMAT, JarAnalyzer.DEPENDENCY_ECOSYSTEM);
    }

    // FIXME: customized detection logic, as the default analysers are not setting name and version sanely

    // FIXME: the JarAnalyzer does some pretty odd things with evidence like "groupid" which does not actually use
    // FIXME: ... the data from models given but transforms it :-\
    // FIXME: It however when setting "maven" identifier has what appears to be the original data :-\

    @Nullable
    @Override
    protected PackageUrl doDetect(final Dependency dependency) {
        String group = null;
        String name = dependency.getName();
        String version = dependency.getVersion();

        if (name == null || version == null) {
            // when a "maven" identifier exists, prefer that
            Identifier mid = findIdentifier(dependency, "maven");
            if (mid != null) {
                // expected to be "<g>:<a>:<v>"
                String[] parts = mid.getValue().split(":", 3);
                if (parts.length == 3) {
                    group = parts[0];
                    name = parts[1];
                    version = parts[2];
                }
            }
        }

        // TODO: may want to first consider just "central" and "nexus" sources, then guess from other evidence?

        // else try to extract from evidence, which may be incorrect due to how evidence is gathered and classified
        if (name == null) {
            Evidence gid = new EvidenceExtractor()
                    .types(EvidenceType.VENDOR, EvidenceType.PRODUCT)
                    .names("groupid")
                    .sources("central", "nexus", "pom")
                    .extract(dependency);

            Evidence aid = new EvidenceExtractor()
                    .types(EvidenceType.VENDOR, EvidenceType.PRODUCT)
                    .names("artifactid")
                    .sources("central", "nexus", "pom")
                    .extract(dependency);

            if (gid != null && aid != null) {
                group = gid.getValue();
                name = aid.getValue();
            }
        }

        if (version == null) {
            Evidence e = new EvidenceExtractor()
                    .types(EvidenceType.VERSION)
                    .names("version")
                    .sources("central", "nexus", "pom")
                    .extract(dependency);
            if (e != null) {
                version = e.getValue();
            }
        }

        if (name != null && version != null) {
            return new PackageUrl.Builder()
                    .type(format)
                    .namespace(group)
                    .name(name)
                    .version(version)
                    .build();
        }

        return null;
    }
}
