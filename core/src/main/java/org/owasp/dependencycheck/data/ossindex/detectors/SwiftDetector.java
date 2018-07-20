package org.owasp.dependencycheck.data.ossindex.detectors;

import org.owasp.dependencycheck.analyzer.CocoaPodsAnalyzer;
import org.owasp.dependencycheck.analyzer.SwiftPackageManagerAnalyzer;
import org.owasp.dependencycheck.data.ossindex.PackageDetector;

/**
 * Swift {@link PackageDetector}.
 *
 * @since ???
 */
public class SwiftDetector extends PackageDetectorSupport {
    public static final String FORMAT = "swift";

    // FIXME: looks like many swift dependencies may be missing version information, unsure why

    // TODO: resolve cocoapods vs. swift are these different package systems?

    public SwiftDetector() {
        super(FORMAT, CocoaPodsAnalyzer.DEPENDENCY_ECOSYSTEM, SwiftPackageManagerAnalyzer.DEPENDENCY_ECOSYSTEM);
    }
}
