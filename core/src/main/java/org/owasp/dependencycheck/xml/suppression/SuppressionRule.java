/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.suppression;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.annotation.concurrent.NotThreadSafe;
import javax.xml.bind.DatatypeConverter;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;

/**
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class SuppressionRule {

    /**
     * The file path for the suppression.
     */
    private PropertyType filePath;

    /**
     * The SHA1 hash.
     */
    private String sha1;
    /**
     * A list of CPEs to suppression
     */
    private List<PropertyType> cpe = new ArrayList<>();
    /**
     * The list of cvssBelow scores.
     */
    private List<Float> cvssBelow = new ArrayList<>();
    /**
     * The list of CWE entries to suppress.
     */
    private List<String> cwe = new ArrayList<>();
    /**
     * The list of CVE entries to suppress.
     */
    private List<String> cve = new ArrayList<>();
    /**
     * A Maven GAV to suppression.
     */
    private PropertyType gav = null;
    /**
     * The notes added in suppression file
     */

    private String notes;

    /**
     * A flag indicating whether or not the suppression rule is a core/base rule
     * that should not be included in the resulting report in the "suppressed"
     * section.
     */
    private boolean base;

    /**
     * A date until which the suppression is to be retained. This can be used to
     * make a temporary suppression that auto-expires to suppress a CVE while
     * waiting for the vulnerability fix of the dependency to be released.
     */
    private Calendar until;

    /**
     * Get the (@code{nullable}) value of until.
     *
     * @return the value of until
     */
    public Calendar getUntil() {
        return until;
    }

    /**
     * Set the value of until.
     *
     * @param until new value of until
     */
    public void setUntil(Calendar until) {
        this.until = until;
    }

    /**
     * Get the value of filePath.
     *
     * @return the value of filePath
     */
    public PropertyType getFilePath() {
        return filePath;
    }

    /**
     * Set the value of filePath.
     *
     * @param filePath new value of filePath
     */
    public void setFilePath(PropertyType filePath) {
        this.filePath = filePath;
    }

    /**
     * Get the value of sha1.
     *
     * @return the value of sha1
     */
    public String getSha1() {
        return sha1;
    }

    /**
     * Set the value of SHA1.
     *
     * @param sha1 new value of SHA1
     */
    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    /**
     * Get the value of CPE.
     *
     * @return the value of CPE
     */
    public List<PropertyType> getCpe() {
        return cpe;
    }

    /**
     * Set the value of CPE.
     *
     * @param cpe new value of CPE
     */
    public void setCpe(List<PropertyType> cpe) {
        this.cpe = cpe;
    }

    /**
     * Adds the CPE to the CPE list.
     *
     * @param cpe the CPE to add
     */
    public void addCpe(PropertyType cpe) {
        this.cpe.add(cpe);
    }

    /**
     * Returns whether or not this suppression rule as CPE entries.
     *
     * @return whether or not this suppression rule as CPE entries
     */
    public boolean hasCpe() {
        return !cpe.isEmpty();
    }

    /**
     * Get the value of cvssBelow.
     *
     * @return the value of cvssBelow
     */
    public List<Float> getCvssBelow() {
        return cvssBelow;
    }

    /**
     * Set the value of cvssBelow.
     *
     * @param cvssBelow new value of cvssBelow
     */
    public void setCvssBelow(List<Float> cvssBelow) {
        this.cvssBelow = cvssBelow;
    }

    /**
     * Adds the CVSS to the cvssBelow list.
     *
     * @param cvss the CVSS to add
     */
    public void addCvssBelow(Float cvss) {
        this.cvssBelow.add(cvss);
    }

    /**
     * Returns whether or not this suppression rule has CVSS suppressions.
     *
     * @return whether or not this suppression rule has CVSS suppressions
     */
    public boolean hasCvssBelow() {
        return !cvssBelow.isEmpty();
    }

    /**
     * Get the value of notes.
     *
     * @return the value of notes
     */
    public String getNotes() {
        return notes;
    }

    /**
     * Set the value of notes.
     *
     * @param notes new value of cve
     */
    public void setNotes(String notes) {
        this.notes = notes;
    }

    /**
     * Adds the notes to the cve list.
     *
     * @param notes the cve to add
     */
    public void addNotes(String notes) {
        this.notes = notes;
    }

    /**
     * Returns whether this suppression rule has notes entries.
     *
     * @return whether this suppression rule has notes entries
     */
    public boolean hasNotes() {
        return !cve.isEmpty();
    }

    /**
     * Get the value of CWE.
     *
     * @return the value of CWE
     */
    public List<String> getCwe() {
        return cwe;
    }

    /**
     * Set the value of CWE.
     *
     * @param cwe new value of CWE
     */
    public void setCwe(List<String> cwe) {
        this.cwe = cwe;
    }

    /**
     * Adds the CWE to the CWE list.
     *
     * @param cwe the CWE to add
     */
    public void addCwe(String cwe) {
        this.cwe.add(cwe);
    }

    /**
     * Returns whether this suppression rule has CWE entries.
     *
     * @return whether this suppression rule has CWE entries
     */
    public boolean hasCwe() {
        return !cwe.isEmpty();
    }

    /**
     * Get the value of CVE.
     *
     * @return the value of CVE
     */
    public List<String> getCve() {
        return cve;
    }

    /**
     * Set the value of CVE.
     *
     * @param cve new value of CVE
     */
    public void setCve(List<String> cve) {
        this.cve = cve;
    }

    /**
     * Adds the CVE to the CVE list.
     *
     * @param cve the CVE to add
     */
    public void addCve(String cve) {
        this.cve.add(cve);
    }

    /**
     * Returns whether this suppression rule has CVE entries.
     *
     * @return whether this suppression rule has CVE entries
     */
    public boolean hasCve() {
        return !cve.isEmpty();
    }

    /**
     * Get the value of Maven GAV.
     *
     * @return the value of GAV
     */
    public PropertyType getGav() {
        return gav;
    }

    /**
     * Set the value of Maven GAV.
     *
     * @param gav new value of Maven GAV
     */
    public void setGav(PropertyType gav) {
        this.gav = gav;
    }

    /**
     * Returns whether or not this suppression rule as GAV entries.
     *
     * @return whether or not this suppression rule as GAV entries
     */
    public boolean hasGav() {
        return gav != null;
    }

    /**
     * Get the value of base.
     *
     * @return the value of base
     */
    public boolean isBase() {
        return base;
    }

    /**
     * Set the value of base.
     *
     * @param base new value of base
     */
    public void setBase(boolean base) {
        this.base = base;
    }

    /**
     * Processes a given dependency to determine if any CPE, CVE, CWE, or CVSS
     * scores should be suppressed. If any should be, they are removed from the
     * dependency.
     *
     * @param dependency a project dependency to analyze
     */
    public void process(Dependency dependency) {
        if (filePath != null && !filePath.matches(dependency.getFilePath())) {
            return;
        }
        if (sha1 != null && !sha1.equalsIgnoreCase(dependency.getSha1sum())) {
            return;
        }
        if (gav != null) {
            final Iterator<Identifier> itr = dependency.getIdentifiers().iterator();
            boolean gavFound = false;
            while (itr.hasNext()) {
                final Identifier i = itr.next();
                if (identifierMatches("maven", this.gav, i)) {
                    gavFound = true;
                    break;
                }
            }
            if (!gavFound) {
                return;
            }
        }

        if (this.hasCpe()) {
            final Set<Identifier> removalList = new HashSet<>();
            for (Identifier i : dependency.getIdentifiers()) {
                for (PropertyType c : this.cpe) {
                    if (identifierMatches("cpe", c, i)) {
                        if (!isBase()) {
                            if (this.notes != null) {
                                i.setNotes(this.notes);
                            }
                            dependency.addSuppressedIdentifier(i);
                        }
                        removalList.add(i);
                        break;
                    }
                }
            }
            for (Identifier i : removalList) {
                dependency.removeIdentifier(i);
            }
        }
        if (hasCve() || hasCwe() || hasCvssBelow()) {
            final Set<Vulnerability> removeVulns = new HashSet<>();
            for (Vulnerability v : dependency.getVulnerabilities()) {
                boolean remove = false;
                for (String entry : this.cve) {
                    if (entry.equalsIgnoreCase(v.getName())) {
                        removeVulns.add(v);
                        remove = true;
                        break;
                    }
                }
                if (!remove) {
                    for (String entry : this.cwe) {
                        if (v.getCwe() != null) {
                            final String toMatch = String.format("CWE-%s", entry);
                            String toTest = v.getCwe();
                            if (toTest.contains(" ")) {
                                toTest = toTest.substring(0, toTest.indexOf(" ")).toUpperCase();
                            }
                            if (toTest.equals(toMatch)) {
                                remove = true;
                                removeVulns.add(v);
                                break;
                            }
                        }
                    }
                }
                if (!remove) {
                    for (float cvss : this.cvssBelow) {
                        if (v.getCvssScore() < cvss) {
                            remove = true;
                            removeVulns.add(v);
                            break;
                        }
                    }
                }
                if (remove) {
                    if (!isBase()) {
                        if (this.notes != null) {
                            v.setNotes(this.notes);
                        }
                        dependency.addSuppressedVulnerability(v);
                    }
                }
            }
            for (Vulnerability v : removeVulns) {
                dependency.removeVulnerability(v);
            }
        }
    }

    /**
     * Identifies if the cpe specified by the cpe suppression rule does not
     * specify a version.
     *
     * @param c a suppression rule identifier
     * @return true if the property type does not specify a version; otherwise
     * false
     */
    protected boolean cpeHasNoVersion(PropertyType c) {
        return !c.isRegex() && countCharacter(c.getValue(), ':') <= 3;
    }

    /**
     * Counts the number of occurrences of the character found within the
     * string.
     *
     * @param str the string to check
     * @param c the character to count
     * @return the number of times the character is found in the string
     */
    private int countCharacter(String str, char c) {
        int count = 0;
        int pos = str.indexOf(c) + 1;
        while (pos > 0) {
            count += 1;
            pos = str.indexOf(c, pos) + 1;
        }
        return count;
    }

    /**
     * Determines if the cpeEntry specified as a PropertyType matches the given
     * Identifier.
     *
     * @param identifierType the type of identifier ("cpe", "maven", etc.)
     * @param suppressionEntry a suppression rule entry
     * @param identifier a CPE identifier to check
     * @return true if the entry matches; otherwise false
     */
    protected boolean identifierMatches(String identifierType, PropertyType suppressionEntry, Identifier identifier) {
        if (identifierType.equals(identifier.getType())) {
            if (suppressionEntry.matches(identifier.getValue())) {
                return true;
            } else if ("cpe".equals(identifierType) && cpeHasNoVersion(suppressionEntry)) {
                if (suppressionEntry.isCaseSensitive()) {
                    return identifier.getValue().startsWith(suppressionEntry.getValue());
                } else {
                    final String id = identifier.getValue().toLowerCase();
                    final String check = suppressionEntry.getValue().toLowerCase();
                    return id.startsWith(check);
                }
            }
        }
        return false;
    }

    /**
     * Standard toString implementation.
     *
     * @return a string representation of this object
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(64);
        sb.append("SuppressionRule{");
        if (until != null) {
            sb.append("until=").append(DatatypeConverter.printDate(until)).append(',');
        }
        if (filePath != null) {
            sb.append("filePath=").append(filePath).append(',');
        }
        if (sha1 != null) {
            sb.append("sha1=").append(sha1).append(',');
        }
        if (gav != null) {
            sb.append("gav=").append(gav).append(',');
        }
        if (cpe != null && !cpe.isEmpty()) {
            sb.append("cpe={");
            for (PropertyType pt : cpe) {
                sb.append(pt).append(',');
            }
            sb.append('}');
        }
        if (cwe != null && !cwe.isEmpty()) {
            sb.append("cwe={");
            for (String s : cwe) {
                sb.append(s).append(',');
            }
            sb.append('}');
        }
        if (cve != null && !cve.isEmpty()) {
            sb.append("cve={");
            for (String s : cve) {
                sb.append(s).append(',');
            }
            sb.append('}');
        }
        if (cvssBelow != null && !cvssBelow.isEmpty()) {
            sb.append("cvssBelow={");
            for (Float s : cvssBelow) {
                sb.append(s).append(',');
            }
            sb.append('}');
        }
        sb.append('}');
        return sb.toString();
    }
}
