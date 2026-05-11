/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.scripts;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Unit tests for {@link PyGhidraNotAvailableException}.
 *
 * Signals that Python scripting cannot run because the JVM was not bootstrapped
 * via PyGhidra (PyGhidraScriptProvider's static scriptRunner is null). Carries
 * a human-readable message suitable for relay to MCP clients.
 */
public class PyGhidraNotAvailableExceptionTest {

    @Test
    public void messageConstructorPreservesMessage() {
        PyGhidraNotAvailableException ex =
            new PyGhidraNotAvailableException("Python is not available");
        assertEquals("Python is not available", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    public void messageAndCauseConstructorPreservesBoth() {
        Throwable cause = new RuntimeException("underlying");
        PyGhidraNotAvailableException ex =
            new PyGhidraNotAvailableException("wrapper", cause);
        assertEquals("wrapper", ex.getMessage());
        assertSame(cause, ex.getCause());
    }

    @Test
    public void isCheckedException() {
        // Verifies the class extends Exception (checked) rather than
        // RuntimeException, so callers must explicitly handle it.
        assertTrue(Exception.class.isAssignableFrom(PyGhidraNotAvailableException.class));
        assertFalse(RuntimeException.class.isAssignableFrom(PyGhidraNotAvailableException.class));
    }
}
