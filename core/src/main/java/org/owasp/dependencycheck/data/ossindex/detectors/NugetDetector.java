package org.owasp.dependencycheck.data.ossindex.detectors;

import org.owasp.dependencycheck.analyzer.NuspecAnalyzer;
import org.owasp.dependencycheck.data.ossindex.EvidenceExtractor;
import org.owasp.dependencycheck.data.ossindex.PackageDetector;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.sonatype.goodies.packageurl.PackageUrl;

import javax.annotation.Nullable;

/**
 * NuGET {@link PackageDetector}.
 *
 * @since ???
 */
public class NugetDetector extends PackageDetectorSupport {
    public static final String NUGET = "nuget";

    public NugetDetector() {
        super(NUGET, NuspecAnalyzer.DEPENDENCY_ECOSYSTEM);
    }

    // FIXME: customized detection logic, as the default analysers are not setting name and version sanely

    @Nullable
    @Override
    protected PackageUrl doDetect(final Dependency dependency) {
        String name = dependency.getName();
        if (name == null) {
            // FIXME: looks like extraction of name, may lead to name+version in some cases
            Evidence e = new EvidenceExtractor()
                    .types(EvidenceType.PRODUCT)
                    .names("product", "name")
                    .sources("grokassembly", "file")
                    .extract(dependency);
            if (e != null) {
                name = e.getValue();
            }
        }

        String version = dependency.getVersion();
        if (version == null) {
            Evidence e = new EvidenceExtractor()
                    .types(EvidenceType.VERSION)
                    .names("version")
                    .sources("grokassembly", "file")
                    .extract(dependency);
            if (e != null) {
                version = e.getValue();
            }
        }

        if (name != null && version != null) {
            return new PackageUrl.Builder()
                    .type(format)
                    .name(name)
                    .version(version)
                    .build();
        }

        return null;
    }
}
