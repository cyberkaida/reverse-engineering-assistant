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
package reva.util;

/**
 * Small helpers for reasoning about server bind addresses.
 */
public final class NetworkUtil {

    private NetworkUtil() {
    }

    /**
     * Whether the given bind host refers to the local loopback interface only.
     * Wildcard binds (0.0.0.0, ::) are NOT localhost — they expose all interfaces.
     *
     * @param host the bind host string (e.g. "127.0.0.1", "0.0.0.0", "localhost")
     * @return true if the host is a loopback/localhost address
     */
    public static boolean isLocalhostAddress(String host) {
        if (host == null) {
            return false;
        }
        String h = host.trim();
        if (h.isEmpty()) {
            return false;
        }
        if (h.equalsIgnoreCase("localhost") || h.equals("::1")) {
            return true;
        }
        return h.startsWith("127.");
    }
}
