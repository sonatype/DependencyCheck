package org.owasp.dependencycheck.data.ossindex;

import org.owasp.dependencycheck.dependency.Dependency;
import org.sonatype.goodies.packageurl.PackageUrl;

import javax.annotation.Nullable;

/**
 * Detect {@link PackageUrl} from {@link Dependency}.
 *
 * @since ???
 */
public interface PackageDetector
{
    @Nullable
    PackageUrl detect(Dependency dependency);
}
