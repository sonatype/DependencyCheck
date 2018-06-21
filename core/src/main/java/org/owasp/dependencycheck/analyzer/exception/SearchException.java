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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer.exception;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception thrown when an online searching fails (such as NSP).
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class SearchException extends AnalysisException {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new SearchException.
     */
    public SearchException() {
        super();
    }

    /**
     * Creates a new SearchException.
     *
     * @param msg a message for the exception.
     */
    public SearchException(String msg) {
        super(msg);
    }

    /**
     * Creates a new SearchException.
     *
     * @param ex the cause of the failure.
     */
    public SearchException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new SearchException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the failure.
     */
    public SearchException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
