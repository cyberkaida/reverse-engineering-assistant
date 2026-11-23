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
package reva.decompiler;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;
import org.mockito.ArgumentCaptor;

import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class DecompilationCacheTest {

    private static final long WAIT_SECONDS = 10;

    private final AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);

    private Program program(AtomicLong modNumber) {
        Program p = mock(Program.class);
        when(p.getModificationNumber()).thenAnswer(inv -> modNumber.get());
        return p;
    }

    private Function function(long offset) {
        Function f = mock(Function.class);
        Address entry = space.getAddress(offset);
        when(f.getEntryPoint()).thenReturn(entry);
        return f;
    }

    private static DecompilationSnapshot snapshot(int chars) {
        return new DecompilationSnapshot("x".repeat(chars), "void f(void)", List.of());
    }

    /** Counts calls and returns a fresh snapshot of the given size each time. */
    private static final class CountingBackend implements DecompilationCache.Backend {
        final AtomicInteger calls = new AtomicInteger();
        final AtomicReference<DecompInterface> lastBorrowed = new AtomicReference<>();
        final int chars;

        CountingBackend(int chars) {
            this.chars = chars;
        }

        @Override
        public DecompilationResult decompile(Program program, Function function, DecompInterface borrowed) {
            calls.incrementAndGet();
            lastBorrowed.set(borrowed);
            return DecompilationResult.success(snapshot(chars));
        }
    }

    private static void awaitHits(DecompilationCache cache, long hits) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
        while (cache.stats().hits() < hits) {
            assertTrue("waiters did not arrive", System.nanoTime() < deadline);
            Thread.onSpinWait();
        }
    }

    @Test
    public void secondGetIsAHit() {
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);

        DecompilationResult first = cache.get(p, f);
        DecompilationResult second = cache.get(p, f);

        assertSame(first.snapshot(), second.snapshot());
        assertEquals(1, backend.calls.get());
        DecompilationCache.Stats s = cache.stats();
        assertEquals(1, s.hits());
        assertEquals(1, s.misses());
        assertEquals(1, s.decompiles());
    }

    @Test
    public void modificationNumberChangeForcesFreshDecompile() {
        AtomicLong mod = new AtomicLong(1);
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(mod);
        Function f = function(0x10);

        DecompilationResult first = cache.get(p, f);
        mod.set(2);
        DecompilationResult second = cache.get(p, f);

        assertNotSame(first.snapshot(), second.snapshot());
        assertEquals(2, backend.calls.get());
        assertEquals(1, cache.stats().entries());
        assertEquals(10, cache.stats().chars());
    }

    @Test
    public void changeDuringDecompileIsNotServedAfterwards() {
        AtomicLong mod = new AtomicLong(1);
        AtomicInteger calls = new AtomicInteger();
        DecompilationCache cache = new DecompilationCache((p, f, b) -> {
            calls.incrementAndGet();
            mod.incrementAndGet();
            return DecompilationResult.success(snapshot(10));
        }, 1000);
        Program p = program(mod);
        Function f = function(0x10);

        cache.get(p, f);
        cache.get(p, f);

        assertEquals(2, calls.get());
    }

    @Test
    public void concurrentGetsShareOneDecompile() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        DecompilationCache cache = new DecompilationCache((p, f, b) -> {
            calls.incrementAndGet();
            entered.countDown();
            try {
                assertTrue(release.await(WAIT_SECONDS, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return DecompilationResult.success(snapshot(10));
        }, 1000);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);

        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<DecompilationResult>> futures = new ArrayList<>();
            futures.add(pool.submit(() -> cache.get(p, f)));
            assertTrue(entered.await(WAIT_SECONDS, TimeUnit.SECONDS));
            for (int i = 0; i < 7; i++) {
                futures.add(pool.submit(() -> cache.get(p, f)));
            }
            awaitHits(cache, 7);
            release.countDown();

            DecompilationSnapshot expected = futures.get(0).get(WAIT_SECONDS, TimeUnit.SECONDS).snapshot();
            assertNotNull(expected);
            for (Future<DecompilationResult> fu : futures) {
                assertSame(expected, fu.get(WAIT_SECONDS, TimeUnit.SECONDS).snapshot());
            }
            assertEquals(1, calls.get());
            assertEquals(1, cache.stats().decompiles());
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    public void failureReachesAllWaitersAndIsNotCached() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        DecompilationCache cache = new DecompilationCache((p, f, b) -> {
            calls.incrementAndGet();
            entered.countDown();
            try {
                assertTrue(release.await(WAIT_SECONDS, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return DecompilationResult.failure("Decompilation timed out after 1 seconds");
        }, 1000);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);

        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Future<DecompilationResult>> futures = new ArrayList<>();
            futures.add(pool.submit(() -> cache.get(p, f)));
            assertTrue(entered.await(WAIT_SECONDS, TimeUnit.SECONDS));
            for (int i = 0; i < 3; i++) {
                futures.add(pool.submit(() -> cache.get(p, f)));
            }
            awaitHits(cache, 3);
            release.countDown();

            for (Future<DecompilationResult> fu : futures) {
                DecompilationResult r = fu.get(WAIT_SECONDS, TimeUnit.SECONDS);
                assertFalse(r.success());
                assertEquals("Decompilation timed out after 1 seconds", r.errorMessage());
            }
            assertEquals(1, calls.get());
            assertEquals(0, cache.stats().entries());
            assertEquals(1, cache.stats().failures());

            cache.get(p, f);
            assertEquals(2, calls.get());
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    public void messagelessExceptionKeepsTodaysText() {
        DecompilationCache cache = new DecompilationCache((p, f, b) -> {
            throw new IllegalStateException();
        }, 1000);
        DecompilationResult r = cache.get(program(new AtomicLong(1)), function(0x10));
        assertEquals(DecompilationResult.FailureKind.EXCEPTION, r.failureKind());
        assertEquals("Exception during decompilation: null", r.errorMessage());
    }

    @Test
    public void exceptionResultCarriesTheCause() {
        IllegalArgumentException boom = new IllegalArgumentException("boom");
        DecompilationCache cache = new DecompilationCache((p, f, b) -> {
            throw boom;
        }, 1000);
        DecompilationResult r = cache.get(program(new AtomicLong(1)), function(0x10));
        assertSame(boom, r.cause());
        assertEquals("Exception during decompilation: boom", r.errorMessage());
        assertNull(DecompilationResult.failure("x").cause());
    }

    @Test
    public void plainFailureIsDecompileFailed() {
        DecompilationResult r = DecompilationResult.failure("Decompilation timed out after 1 seconds");
        assertEquals(DecompilationResult.FailureKind.DECOMPILE_FAILED, r.failureKind());
        assertNull(DecompilationResult.success(null).failureKind());
    }

    @Test
    public void backendExceptionBecomesFailureAndIsNotCached() {
        AtomicInteger calls = new AtomicInteger();
        DecompilationCache cache = new DecompilationCache((p, f, b) -> {
            calls.incrementAndGet();
            throw new IllegalStateException("boom");
        }, 1000);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);

        DecompilationResult r = cache.get(p, f);
        assertFalse(r.success());
        assertEquals("Exception during decompilation: boom", r.errorMessage());
        assertEquals(DecompilationResult.FailureKind.EXCEPTION, r.failureKind());
        cache.get(p, f);
        assertEquals(2, calls.get());
        assertEquals(0, cache.stats().entries());
        assertEquals(2, cache.stats().failures());
    }

    @Test
    public void sameAddressInTwoProgramsDoesNotCollide() {
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p1 = program(new AtomicLong(1));
        Program p2 = program(new AtomicLong(1));
        Function f = function(0x10);

        DecompilationResult r1 = cache.get(p1, f);
        DecompilationResult r2 = cache.get(p2, f);

        assertNotSame(r1.snapshot(), r2.snapshot());
        assertEquals(2, backend.calls.get());
        assertSame(r1.snapshot(), cache.get(p1, f).snapshot());
        assertSame(r2.snapshot(), cache.get(p2, f).snapshot());
        assertEquals(2, backend.calls.get());
        assertEquals(2, cache.stats().entries());
    }

    @Test
    public void boundEvictsLeastRecentlyUsed() {
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 20);
        Program p = program(new AtomicLong(1));
        Function a = function(0x10);
        Function b = function(0x20);
        Function c = function(0x30);

        cache.get(p, a);
        cache.get(p, b);
        cache.get(p, a);
        cache.get(p, c);
        assertEquals(3, backend.calls.get());
        assertEquals(1, cache.stats().evictions());
        assertTrue(cache.stats().chars() <= 20);

        cache.get(p, a);
        cache.get(p, c);
        assertEquals(3, backend.calls.get());
        cache.get(p, b);
        assertEquals(4, backend.calls.get());
        assertTrue(cache.stats().chars() <= 20);
    }

    @Test
    public void oversizedSnapshotIsReturnedButNotStored() {
        CountingBackend backend = new CountingBackend(50);
        DecompilationCache cache = new DecompilationCache(backend, 20);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);

        DecompilationResult r = cache.get(p, f);
        assertTrue(r.success());
        assertEquals(0, cache.stats().entries());
        assertEquals(0, cache.stats().chars());
        cache.get(p, f);
        assertEquals(2, backend.calls.get());
    }

    @Test
    public void dropProgramRemovesOnlyThatProgram() {
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p1 = program(new AtomicLong(1));
        Program p2 = program(new AtomicLong(1));
        Function f = function(0x10);
        cache.get(p1, f);
        cache.get(p2, f);

        cache.dropProgram(p1);

        assertEquals(1, cache.stats().entries());
        assertEquals(10, cache.stats().chars());
        cache.get(p2, f);
        assertEquals(2, backend.calls.get());
        cache.get(p1, f);
        assertEquals(3, backend.calls.get());
    }

    @Test
    public void putFillsCurrentState() {
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);
        DecompilationSnapshot s = snapshot(5);

        cache.put(p, f, s, 1);

        assertSame(s, cache.get(p, f).snapshot());
        assertEquals(0, backend.calls.get());
        assertEquals(1, cache.stats().entries());
    }

    @Test
    public void putWithOutdatedNumberIsIgnored() {
        AtomicLong mod = new AtomicLong(1);
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(mod);
        Function f = function(0x10);

        long before = p.getModificationNumber();
        mod.incrementAndGet();
        cache.put(p, f, snapshot(5), before);

        assertEquals(0, cache.stats().entries());
        cache.get(p, f);
        assertEquals(1, backend.calls.get());
    }

    @Test
    public void putPurgesEntriesOfOlderState() {
        AtomicLong mod = new AtomicLong(1);
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(mod);
        cache.get(p, function(0x10));
        assertEquals(1, cache.stats().entries());

        mod.set(2);
        DecompilationSnapshot s = snapshot(5);
        Function g = function(0x20);
        cache.put(p, g, s, 2);

        assertEquals(1, cache.stats().entries());
        assertEquals(5, cache.stats().chars());
        assertSame(s, cache.get(p, g).snapshot());
    }

    @Test
    public void olderNumberRequestDoesNotRollBackState() {
        AtomicInteger reads = new AtomicInteger();
        long[] sequence = {2, 2, 1, 2};
        Program p = mock(Program.class);
        when(p.getModificationNumber()).thenAnswer(inv -> {
            int i = reads.getAndIncrement();
            return sequence[Math.min(i, sequence.length - 1)];
        });
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Function f = function(0x10);

        DecompilationSnapshot current = cache.get(p, f).snapshot(); // reads 2 (get), 2 (finish)
        DecompilationResult older = cache.get(p, f);                // reads 1 (get), 2 (finish)
        assertTrue(older.success());
        assertNotSame(current, older.snapshot());
        assertEquals(2, backend.calls.get());
        assertEquals(1, cache.stats().entries());

        assertSame(current, cache.get(p, f).snapshot());            // reads 2: still a hit
        assertEquals(2, backend.calls.get());
    }

    @Test
    public void finishFailureStillCompletesFlight() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        AtomicBoolean throwNext = new AtomicBoolean();
        Program p = mock(Program.class);
        when(p.getModificationNumber()).thenAnswer(inv -> {
            if (throwNext.compareAndSet(true, false)) {
                throw new IllegalStateException("program closed");
            }
            return 1L;
        });
        DecompilationCache cache = new DecompilationCache((pr, f, b) -> {
            calls.incrementAndGet();
            entered.countDown();
            try {
                assertTrue(release.await(WAIT_SECONDS, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return DecompilationResult.success(snapshot(10));
        }, 1000);
        Function f = function(0x10);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<DecompilationResult> leader = pool.submit(() -> cache.get(p, f));
            assertTrue(entered.await(WAIT_SECONDS, TimeUnit.SECONDS));
            Future<DecompilationResult> waiter = pool.submit(() -> cache.get(p, f));
            awaitHits(cache, 1);
            throwNext.set(true);
            release.countDown();

            DecompilationResult w = waiter.get(WAIT_SECONDS, TimeUnit.SECONDS);
            DecompilationResult l = leader.get(WAIT_SECONDS, TimeUnit.SECONDS);
            assertFalse(w.success());
            assertFalse(l.success());
            assertEquals("Exception during decompilation: program closed", w.errorMessage());
            assertEquals(DecompilationResult.FailureKind.EXCEPTION, w.failureKind());
            assertEquals(0, cache.stats().entries());

            assertTrue(cache.get(p, f).success());
            assertEquals(2, calls.get());
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    public void interruptedWaiterReturnsAndDecompileStillCompletes() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        DecompilationCache cache = new DecompilationCache((pr, fn, b) -> {
            calls.incrementAndGet();
            entered.countDown();
            try {
                assertTrue(release.await(WAIT_SECONDS, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return DecompilationResult.success(snapshot(10));
        }, 1000);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);

        ExecutorService pool = Executors.newFixedThreadPool(1);
        AtomicReference<DecompilationResult> waiterResult = new AtomicReference<>();
        AtomicBoolean waiterStillInterrupted = new AtomicBoolean();
        CountDownLatch waiterDone = new CountDownLatch(1);
        Thread waiter = new Thread(() -> {
            waiterResult.set(cache.get(p, f));
            waiterStillInterrupted.set(Thread.currentThread().isInterrupted());
            waiterDone.countDown();
        });
        try {
            Future<DecompilationResult> leader = pool.submit(() -> cache.get(p, f));
            assertTrue(entered.await(WAIT_SECONDS, TimeUnit.SECONDS));
            waiter.start();
            awaitHits(cache, 1);
            waiter.interrupt();
            assertTrue(waiterDone.await(WAIT_SECONDS, TimeUnit.SECONDS));

            assertFalse(waiterResult.get().success());
            assertEquals("Interrupted while waiting for decompilation", waiterResult.get().errorMessage());
            assertTrue(waiterStillInterrupted.get());
            assertEquals(0, cache.stats().entries());

            release.countDown();
            DecompilationResult l = leader.get(WAIT_SECONDS, TimeUnit.SECONDS);
            assertTrue(l.success());
            assertEquals(1, cache.stats().entries());
            assertSame(l.snapshot(), cache.get(p, f).snapshot());
            assertEquals(1, calls.get());
        } finally {
            release.countDown();
            pool.shutdownNow();
            waiter.interrupt();
        }
    }

    private static DomainObjectClosedListener registeredListener(Program p, int times) {
        ArgumentCaptor<DomainObjectClosedListener> captor = ArgumentCaptor.forClass(DomainObjectClosedListener.class);
        verify(p, times(times)).addCloseListener(captor.capture());
        return captor.getValue();
    }

    @Test
    public void creatingStateRegistersOneCloseListener() {
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(new AtomicLong(1));

        cache.get(p, function(0x10));
        cache.get(p, function(0x20));
        cache.get(p, function(0x10));

        assertNotNull(registeredListener(p, 1));
    }

    @Test
    public void closeListenerDropsOnlyThatProgram() {
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p1 = program(new AtomicLong(1));
        Program p2 = program(new AtomicLong(1));
        Function f = function(0x10);
        cache.get(p1, f);
        cache.get(p1, function(0x20));
        cache.get(p2, f);
        assertEquals(3, cache.stats().entries());

        registeredListener(p1, 1).domainObjectClosed(p1);

        assertEquals(1, cache.stats().entries());
        assertEquals(10, cache.stats().chars());
        cache.get(p2, f);
        assertEquals("p2 is still a hit", 3, backend.calls.get());
        cache.get(p1, f);
        assertEquals("p1 decompiles afresh", 4, backend.calls.get());
        registeredListener(p1, 2);
    }

    @Test
    public void dropProgramRemovesItsCloseListener() {
        DecompilationCache cache = new DecompilationCache(new CountingBackend(10), 1000);
        Program p = program(new AtomicLong(1));
        cache.get(p, function(0x10));
        DomainObjectClosedListener listener = registeredListener(p, 1);

        cache.dropProgram(p);

        verify(p).removeCloseListener(listener);
    }

    @Test
    public void listenerOfADroppedStateLeavesTheNewStateAlone() {
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);
        cache.get(p, f);
        DomainObjectClosedListener old = registeredListener(p, 1);
        cache.dropProgram(p);
        cache.get(p, f);
        assertEquals(1, cache.stats().entries());

        old.domainObjectClosed(p);

        assertEquals(1, cache.stats().entries());
        cache.get(p, f);
        assertEquals(2, backend.calls.get());
    }

    /** Backend whose n-th call (from 0) waits for release[n] and returns a snapshot of size sizes[n]. */
    private static final class GatedBackend implements DecompilationCache.Backend {
        final AtomicInteger calls = new AtomicInteger();
        final CountDownLatch[] entered;
        final CountDownLatch[] release;
        final int[] sizes;
        final Runnable[] during;

        GatedBackend(int... sizes) {
            this.sizes = sizes;
            entered = new CountDownLatch[sizes.length];
            release = new CountDownLatch[sizes.length];
            during = new Runnable[sizes.length];
            for (int i = 0; i < sizes.length; i++) {
                entered[i] = new CountDownLatch(1);
                release[i] = new CountDownLatch(1);
            }
        }

        @Override
        public DecompilationResult decompile(Program program, Function function, DecompInterface borrowed) {
            int n = calls.getAndIncrement();
            entered[n].countDown();
            try {
                assertTrue("test did not release call " + n, release[n].await(WAIT_SECONDS, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (during[n] != null) {
                during[n].run();
            }
            return DecompilationResult.success(snapshot(sizes[n]));
        }

        void releaseAll() {
            for (CountDownLatch l : release) {
                l.countDown();
            }
        }
    }

    @Test
    public void dropDuringInFlightDecompileReturnsButDoesNotStore() throws Exception {
        GatedBackend backend = new GatedBackend(11, 22);
        backend.release[1].countDown();
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<DecompilationResult> leader = pool.submit(() -> cache.get(p, f));
            assertTrue(backend.entered[0].await(WAIT_SECONDS, TimeUnit.SECONDS));
            Future<DecompilationResult> waiter = pool.submit(() -> cache.get(p, f));
            awaitHits(cache, 1);

            cache.dropProgram(p);
            backend.release[0].countDown();

            DecompilationResult l = leader.get(WAIT_SECONDS, TimeUnit.SECONDS);
            assertTrue(l.success());
            assertEquals(11, l.snapshot().code().length());
            assertSame("The waiter shares the flight's result", l.snapshot(),
                waiter.get(WAIT_SECONDS, TimeUnit.SECONDS).snapshot());
            assertEquals("Not stored after the drop", 0, cache.stats().entries());
            assertEquals(0, cache.stats().chars());

            DecompilationResult next = cache.get(p, f);
            assertEquals(22, next.snapshot().code().length());
            assertEquals(2, backend.calls.get());
        } finally {
            backend.releaseAll();
            pool.shutdownNow();
        }
    }

    @Test
    public void dropAndNewStateDuringInFlightDecompileDoesNotReceiveTheOldResult() throws Exception {
        GatedBackend backend = new GatedBackend(11, 22);
        backend.release[1].countDown();
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);

        ExecutorService pool = Executors.newFixedThreadPool(1);
        try {
            Future<DecompilationResult> leader = pool.submit(() -> cache.get(p, f));
            assertTrue(backend.entered[0].await(WAIT_SECONDS, TimeUnit.SECONDS));
            cache.dropProgram(p);
            DecompilationResult fresh = cache.get(p, f); // new state, same number; second backend call
            assertEquals(22, fresh.snapshot().code().length());
            backend.release[0].countDown();
            assertEquals(11, leader.get(WAIT_SECONDS, TimeUnit.SECONDS).snapshot().code().length());

            assertEquals(1, cache.stats().entries());
            assertSame("The dropped flight did not replace the new state's entry", fresh.snapshot(),
                cache.get(p, f).snapshot());
            assertEquals(2, backend.calls.get());
        } finally {
            backend.releaseAll();
            pool.shutdownNow();
        }
    }

    private void newLeaderAfterChange(boolean oldLeaderFinishesFirst) throws Exception {
        AtomicLong mod = new AtomicLong(1);
        GatedBackend backend = new GatedBackend(11, 22);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(mod);
        Function f = function(0x10);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<DecompilationResult> oldLeader = pool.submit(() -> cache.get(p, f));
            assertTrue(backend.entered[0].await(WAIT_SECONDS, TimeUnit.SECONDS));
            mod.set(2);
            Future<DecompilationResult> newLeader = pool.submit(() -> cache.get(p, f));
            assertTrue("A request after the change leads its own decompile",
                backend.entered[1].await(WAIT_SECONDS, TimeUnit.SECONDS));

            DecompilationResult o;
            DecompilationResult n;
            if (oldLeaderFinishesFirst) {
                backend.release[0].countDown();
                o = oldLeader.get(WAIT_SECONDS, TimeUnit.SECONDS);
                assertEquals("Old result not stored", 0, cache.stats().entries());
                backend.release[1].countDown();
                n = newLeader.get(WAIT_SECONDS, TimeUnit.SECONDS);
            } else {
                backend.release[1].countDown();
                n = newLeader.get(WAIT_SECONDS, TimeUnit.SECONDS);
                backend.release[0].countDown();
                o = oldLeader.get(WAIT_SECONDS, TimeUnit.SECONDS);
            }
            assertEquals(11, o.snapshot().code().length());
            assertEquals(22, n.snapshot().code().length());
            assertEquals(1, cache.stats().entries());
            assertEquals(22, cache.stats().chars());
            assertSame("The new result is stored and served", n.snapshot(), cache.get(p, f).snapshot());
            assertEquals(2, backend.calls.get());
        } finally {
            backend.releaseAll();
            pool.shutdownNow();
        }
    }

    @Test
    public void newLeaderAfterChangeOldLeaderFinishesFirst() throws Exception {
        newLeaderAfterChange(true);
    }

    @Test
    public void newLeaderAfterChangeOldLeaderFinishesLast() throws Exception {
        newLeaderAfterChange(false);
    }

    @Test
    public void waiterGivesUpOnABlockedLeaderAndDecompilesItself() throws Exception {
        GatedBackend backend = new GatedBackend(11, 22);
        backend.release[1].countDown();
        DecompilationCache cache = new DecompilationCache(backend, 1000, () -> 50L);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<DecompilationResult> leader = pool.submit(() -> cache.get(p, f));
            assertTrue(backend.entered[0].await(WAIT_SECONDS, TimeUnit.SECONDS));

            DecompilationResult w = pool.submit(() -> cache.get(p, f)).get(WAIT_SECONDS, TimeUnit.SECONDS);
            assertTrue(w.success());
            assertEquals("The waiter's own decompile", 22, w.snapshot().code().length());
            assertEquals(2, backend.calls.get());
            assertEquals(2, cache.stats().decompiles());
            assertEquals("Stored: the number did not change", 1, cache.stats().entries());
            assertSame(w.snapshot(), cache.get(p, f).snapshot());
            assertFalse("The leader is still blocked", leader.isDone());

            backend.release[0].countDown();
            DecompilationResult l = leader.get(WAIT_SECONDS, TimeUnit.SECONDS);
            assertTrue(l.success());
            assertEquals(11, l.snapshot().code().length());
            assertEquals(1, cache.stats().entries());
        } finally {
            backend.releaseAll();
            pool.shutdownNow();
        }
    }

    @Test
    public void waiterSoloDecompileIsNotStoredIfTheNumberChanges() throws Exception {
        AtomicLong mod = new AtomicLong(1);
        GatedBackend backend = new GatedBackend(11, 22);
        backend.release[1].countDown();
        backend.during[1] = mod::incrementAndGet;
        DecompilationCache cache = new DecompilationCache(backend, 1000, () -> 50L);
        Program p = program(mod);
        Function f = function(0x10);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<DecompilationResult> leader = pool.submit(() -> cache.get(p, f));
            assertTrue(backend.entered[0].await(WAIT_SECONDS, TimeUnit.SECONDS));

            DecompilationResult w = pool.submit(() -> cache.get(p, f)).get(WAIT_SECONDS, TimeUnit.SECONDS);
            assertTrue("The result is returned to its caller", w.success());
            assertEquals(22, w.snapshot().code().length());
            assertEquals("Computed while the program changed: not stored", 0, cache.stats().entries());

            backend.release[0].countDown();
            assertTrue(leader.get(WAIT_SECONDS, TimeUnit.SECONDS).success());
            assertEquals("The leader's result is outdated too", 0, cache.stats().entries());
        } finally {
            backend.releaseAll();
            pool.shutdownNow();
        }
    }

    @Test
    public void waiterWithinTheBoundSharesTheLeadersResult() throws Exception {
        GatedBackend backend = new GatedBackend(11);
        DecompilationCache cache = new DecompilationCache(backend, 1000,
            () -> TimeUnit.SECONDS.toMillis(WAIT_SECONDS));
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<DecompilationResult> leader = pool.submit(() -> cache.get(p, f));
            assertTrue(backend.entered[0].await(WAIT_SECONDS, TimeUnit.SECONDS));
            Future<DecompilationResult> waiter = pool.submit(() -> cache.get(p, f));
            awaitHits(cache, 1);
            backend.release[0].countDown();

            assertSame(leader.get(WAIT_SECONDS, TimeUnit.SECONDS).snapshot(),
                waiter.get(WAIT_SECONDS, TimeUnit.SECONDS).snapshot());
            assertEquals(1, backend.calls.get());
        } finally {
            backend.releaseAll();
            pool.shutdownNow();
        }
    }

    @Test
    public void defaultWaitBoundIsTheDecompilerTimeoutPlusTheMargin() {
        reva.plugin.ConfigManager config =
            reva.util.RevaInternalServiceRegistry.getService(reva.plugin.ConfigManager.class);
        long timeout = config != null ? config.getDecompilerTimeoutSeconds()
            : reva.plugin.ConfigManager.DEFAULT_DECOMPILER_TIMEOUT_SECONDS;
        assertEquals(TimeUnit.SECONDS.toMillis(timeout + DecompilationCache.WAIT_MARGIN_SECONDS),
            DecompilationCache.configuredWaitBoundMillis());
    }

    @Test
    public void borrowedDecompilerIsPassedThrough() {
        CountingBackend backend = new CountingBackend(10);
        DecompilationCache cache = new DecompilationCache(backend, 1000);
        Program p = program(new AtomicLong(1));
        Function f = function(0x10);
        DecompInterface borrowed = mock(DecompInterface.class);

        cache.get(p, f, borrowed);
        assertSame(borrowed, backend.lastBorrowed.get());

        cache.get(p, function(0x20));
        assertNull(backend.lastBorrowed.get());
    }
}
