package org.owasp.dependencycheck.data.ossindex;

import org.owasp.dependencycheck.dependency.Dependency;

import javax.annotation.Nullable;

/**
 * Detect {@link PackageIdentifier} from {@link Dependency}.
 *
 * @since ???
 */
public interface PackageDetector
{
    @Nullable
    PackageIdentifier detect(Dependency dependency);
}
