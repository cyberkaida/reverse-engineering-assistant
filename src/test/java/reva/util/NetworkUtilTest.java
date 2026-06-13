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

import static org.junit.Assert.*;

import org.junit.Test;

public class NetworkUtilTest {

    @Test
    public void loopbackIpv4IsLocalhost() {
        assertTrue(NetworkUtil.isLocalhostAddress("127.0.0.1"));
        assertTrue(NetworkUtil.isLocalhostAddress("127.5.6.7"));
    }

    @Test
    public void loopbackIpv6IsLocalhost() {
        assertTrue(NetworkUtil.isLocalhostAddress("::1"));
    }

    @Test
    public void localhostHostnameIsLocalhost() {
        assertTrue(NetworkUtil.isLocalhostAddress("localhost"));
        assertTrue(NetworkUtil.isLocalhostAddress("  LocalHost  "));
    }

    @Test
    public void wildcardAndPublicAddressesAreNotLocalhost() {
        assertFalse(NetworkUtil.isLocalhostAddress("0.0.0.0"));
        assertFalse(NetworkUtil.isLocalhostAddress("::"));
        assertFalse(NetworkUtil.isLocalhostAddress("192.168.1.10"));
        assertFalse(NetworkUtil.isLocalhostAddress("10.0.0.5"));
    }

    @Test
    public void nullOrBlankIsNotLocalhost() {
        assertFalse(NetworkUtil.isLocalhostAddress(null));
        assertFalse(NetworkUtil.isLocalhostAddress("   "));
    }
}
