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
package reva;

import static org.junit.Assert.assertNotEquals;

import org.junit.Test;

/**
 * Regression guard for the random-port test infrastructure.
 *
 * <p>Integration tests must bind a random free port (via
 * {@code ConfigManager.setRandomAvailablePort()} in {@link RevaIntegrationTestBase}) instead of
 * the default 8080, so the suite runs alongside a developer/dogfooding ReVa server holding 8080
 * (and so concurrent runs don't collide). If that wiring is ever reverted to the default port,
 * this test fails immediately.
 */
public class RandomPortRegressionIntegrationTest extends RevaIntegrationTestBase {

    @Test
    public void integrationServerBindsRandomPortNotDefault8080() {
        assertNotEquals(
            "Integration tests must bind a random free port, not the default 8080, so they run "
                + "alongside a dev/dogfooding ReVa server on 8080. The wiring lives in "
                + "RevaIntegrationTestBase (setRandomAvailablePort).",
            8080, configManager.getServerPort());
    }
}
