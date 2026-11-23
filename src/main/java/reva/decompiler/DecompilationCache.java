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

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.LongSupplier;

import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import reva.plugin.ConfigManager;
import reva.util.RevaInternalServiceRegistry;

/**
 * Cache of decompilation snapshots keyed on program, function entry point and the program's modification
 * number. Each program holds entries for one modification number only; a request that reads a greater number
 * drops them all (the number only increases, and a request with a smaller one never rolls the state back).
 * Concurrent requests for one function share a single decompile, and no lock is held while the backend runs.
 * A request waits for another request's decompile at most the configured decompiler timeout plus
 * {@link #WAIT_MARGIN_SECONDS}; after that it decompiles for itself.
 * <p>
 * Contract of {@link #get(Program, Function, DecompInterface)}: a non-null {@code borrowed} decompiler must come
 * from {@link ConfiguredDecompiler#open} for the same program. Its result is stored and served to every later
 * caller, so a differently configured decompiler would store a different rendering.
 * <p>
 * Release of a program's entries, in any mode (GUI or headless): when the cache first holds state for a program
 * it registers a close listener on that program, which drops the program's entries when Ghidra closes it.
 * {@link #dropProgram} drops them explicitly (and removes the listener), and the global {@code maxChars} bound
 * limits the total. Programs are additionally held weakly (a {@link WeakHashMap}, which uses equals/hashCode;
 * Ghidra's Program implementations do not override them). That is best-effort only: an {@link Address} in an
 * overlay address space strongly reaches its program, so programs whose cached addresses lie in overlay spaces
 * are released by the close listener, {@code dropProgram} or the bound, not by garbage collection.
 */
public final class DecompilationCache {

    public static final long DEFAULT_MAX_CHARS = 64L * 1024 * 1024;

    /**
     * Added to the configured decompiler timeout to bound how long a request waits for another request's
     * decompile of the same function. The leader's timeout starts only after its decompiler process has started
     * and opened the program, which this margin covers.
     */
    static final long WAIT_MARGIN_SECONDS = 30;

    @FunctionalInterface
    public interface Backend {
        /** borrowed is null unless a bulk tool supplied its own open decompiler. */
        DecompilationResult decompile(Program program, Function function, DecompInterface borrowed);
    }

    public record Stats(long hits, long misses, long decompiles, long failures, long evictions,
                        int entries, long chars) {}

    /** Per-program state. Weakly references its program; see the class comment for the limits of that. */
    private static final class State extends WeakReference<Program> {
        long modNumber;
        boolean dropped;
        final Set<Address> stored = new HashSet<>();
        final Map<Address, Flight> inFlight = new HashMap<>();
        /** Registered on the program; reaches the cache and this state, never the program. */
        DomainObjectClosedListener closeListener;

        State(Program program, ReferenceQueue<Program> queue, long modNumber) {
            super(program, queue);
            this.modNumber = modNumber;
        }
    }

    private record Key(State state, Address address) {}

    private record Entry(DecompilationSnapshot snapshot) {}

    private static final class Flight {
        final long modNumber;
        /** The state the flight was started under; its result may be stored only there. */
        final State state;
        final CompletableFuture<DecompilationResult> future = new CompletableFuture<>();

        Flight(long modNumber, State state) {
            this.modNumber = modNumber;
            this.state = state;
        }
    }

    private final Backend backend;
    private final long maxChars;
    private final LongSupplier waitBoundMillis;

    // All fields below are guarded by lock. Nothing blocking runs under it.
    private final Object lock = new Object();
    private final Map<Program, State> programs = new WeakHashMap<>();
    private final ReferenceQueue<Program> collected = new ReferenceQueue<>();
    private final LinkedHashMap<Key, Entry> lru = new LinkedHashMap<>(16, 0.75f, true);
    private long totalChars;
    private long hits;
    private long misses;
    private long decompiles;
    private long failures;
    private long evictions;

    public DecompilationCache() {
        this(DecompilationCache::decompileWithConfiguredDecompiler, DEFAULT_MAX_CHARS);
    }

    /** The real backend with a custom bound. */
    public DecompilationCache(long maxChars) {
        this(DecompilationCache::decompileWithConfiguredDecompiler, maxChars);
    }

    public DecompilationCache(Backend backend, long maxChars) {
        this(backend, maxChars, DecompilationCache::configuredWaitBoundMillis);
    }

    /** waitBoundMillis: how long a request waits for another's decompile before decompiling for itself. */
    DecompilationCache(Backend backend, long maxChars, LongSupplier waitBoundMillis) {
        this.backend = backend;
        this.maxChars = maxChars;
        this.waitBoundMillis = waitBoundMillis;
    }

    /** The configured decompiler timeout (ConfigManager's default if none is registered) plus the margin. */
    static long configuredWaitBoundMillis() {
        ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
        long timeoutSeconds = config != null ? config.getDecompilerTimeoutSeconds()
            : ConfigManager.DEFAULT_DECOMPILER_TIMEOUT_SECONDS;
        return TimeUnit.SECONDS.toMillis(timeoutSeconds + WAIT_MARGIN_SECONDS);
    }

    public DecompilationResult get(Program program, Function function) {
        return get(program, function, null);
    }

    /**
     * The decompilation of function for the program's current modification number.
     *
     * @param borrowed null, or an open decompiler from {@link ConfiguredDecompiler#open} for this same program,
     *        owned and disposed by the caller (see the class comment)
     */
    public DecompilationResult get(Program program, Function function, DecompInterface borrowed) {
        Address address = function.getEntryPoint();
        // Read before anything else: a result is only ever valid for the number seen before it started.
        long modNumber = program.getModificationNumber();

        Flight flight;
        boolean leader = false;
        synchronized (lock) {
            State state = currentState(program, modNumber);
            if (modNumber < state.modNumber) {
                // Older than the state we hold: never served from or stored into it. Decompile for this
                // caller alone and leave the newer state untouched.
                misses++;
                decompiles++;
                flight = new Flight(modNumber, state);
                leader = true;
            } else {
                Entry entry = lru.get(new Key(state, address));
                if (entry != null) {
                    hits++;
                    return DecompilationResult.success(entry.snapshot());
                }
                flight = state.inFlight.get(address);
                if (flight != null) {
                    hits++;
                } else {
                    misses++;
                    decompiles++;
                    flight = new Flight(modNumber, state);
                    state.inFlight.put(address, flight);
                    leader = true;
                }
            }
        }

        if (!leader) {
            DecompilationResult shared = await(flight);
            if (shared != null) {
                return shared;
            }
            // The leader did not finish within the bound. Decompile for this caller alone: the flight is never
            // registered, so nobody waits on it, and finish stores its result only under the usual rules (its
            // state is still current and the number read before this request is still the program's number).
            Msg.warn(DecompilationCache.class, "Waited too long for another request's decompilation of "
                + function.getName() + "; decompiling separately");
            synchronized (lock) {
                decompiles++;
            }
            flight = new Flight(modNumber, flight.state);
        }

        DecompilationResult result;
        try {
            result = backend.decompile(program, function, borrowed);
            if (result == null) {
                result = DecompilationResult.failure(DecompilationResult.FailureKind.EXCEPTION,
                    "Exception during decompilation: backend returned no result");
            }
        } catch (Exception e) {
            Msg.error(DecompilationCache.class, "Exception during decompilation of " + function.getName(), e);
            result = DecompilationResult.exception("Exception during decompilation: " + e.getMessage(), e);
        } catch (Throwable t) {
            Msg.error(DecompilationCache.class, "Error during decompilation of " + function.getName(), t);
            finish(program, address, flight,
                DecompilationResult.exception("Exception during decompilation: " + t.getMessage(), t));
            throw t;
        }
        return finish(program, address, flight, result);
    }

    /**
     * Store a snapshot the caller produced for the state it read as modificationNumberBeforeDecompile. Ignored
     * unless the program still has that number.
     */
    public void put(Program program, Function function, DecompilationSnapshot snapshot,
            long modificationNumberBeforeDecompile) {
        Address address = function.getEntryPoint();
        long now = program.getModificationNumber();
        if (now != modificationNumberBeforeDecompile) {
            return;
        }
        synchronized (lock) {
            State state = currentState(program, now);
            if (now < state.modNumber) {
                return;
            }
            store(state, address, snapshot);
        }
    }

    public void dropProgram(Program program) {
        synchronized (lock) {
            State state = programs.remove(program);
            if (state != null) {
                discard(state);
                // ListenerSet.remove takes only its own short monitor, which Ghidra does not hold while it
                // invokes close listeners, so calling it under lock cannot deadlock with a closing thread.
                program.removeCloseListener(state.closeListener);
            }
        }
    }

    /** Close-listener callback: drop the state if it is still the program's current one. */
    private void dropState(State state) {
        synchronized (lock) {
            Program program = state.get();
            if (program != null && programs.get(program) == state) {
                programs.remove(program);
            }
            discard(state);
        }
    }

    public Stats stats() {
        synchronized (lock) {
            return new Stats(hits, misses, decompiles, failures, evictions, lru.size(), totalChars);
        }
    }

    /** The flight's result, or null if it did not complete within the wait bound. */
    private DecompilationResult await(Flight flight) {
        try {
            return flight.future.get(waitBoundMillis.getAsLong(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            // The leader may have completed just as the bound passed; use its result if so.
            return flight.future.getNow(null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return DecompilationResult.failure("Interrupted while waiting for decompilation");
        } catch (ExecutionException e) {
            // Flights are only ever completed normally (finish).
            throw new AssertionError("flight completed exceptionally", e);
        }
    }

    /** Always removes the flight and completes its future, even if the bookkeeping throws. */
    private DecompilationResult finish(Program program, Address address, Flight flight,
            DecompilationResult result) {
        DecompilationResult published = result;
        try {
            // Re-read outside the lock; a result computed while the program changed is not stored.
            long now = program.getModificationNumber();
            synchronized (lock) {
                State state = flight.state;
                state.inFlight.remove(address, flight);
                if (!result.success()) {
                    failures++;
                } else if (!state.dropped && state.modNumber == flight.modNumber && now == flight.modNumber) {
                    store(state, address, result.snapshot());
                }
            }
        } catch (RuntimeException e) {
            published = DecompilationResult.exception("Exception during decompilation: " + e.getMessage(), e);
            synchronized (lock) {
                failures++;
            }
        } finally {
            synchronized (lock) {
                flight.state.inFlight.remove(address, flight);
            }
            flight.future.complete(published);
        }
        return published;
    }

    /** Caller holds lock. The state for the program, with entries purged if the number increased. */
    private State currentState(Program program, long modNumber) {
        State dead;
        while ((dead = (State) collected.poll()) != null) {
            discard(dead);
        }
        State state = programs.get(program);
        if (state == null) {
            State created = new State(program, collected, modNumber);
            // Captures the cache and the state only: the program reaches the listener, not the reverse.
            created.closeListener = closed -> dropState(created);
            programs.put(program, created);
            program.addCloseListener(created.closeListener);
            state = created;
        } else if (state.modNumber < modNumber) {
            // The number only increases; a request with an older number never rolls the state back.
            purge(state);
            state.inFlight.clear();
            state.modNumber = modNumber;
        }
        return state;
    }

    /** Caller holds lock. */
    private void store(State state, Address address, DecompilationSnapshot snapshot) {
        Key key = new Key(state, address);
        Entry old = lru.remove(key);
        if (old != null) {
            totalChars -= old.snapshot().sizeInChars();
            state.stored.remove(address);
        }
        long size = snapshot.sizeInChars();
        if (size > maxChars) {
            return;
        }
        lru.put(key, new Entry(snapshot));
        state.stored.add(address);
        totalChars += size;
        Iterator<Map.Entry<Key, Entry>> it = lru.entrySet().iterator();
        while (totalChars > maxChars && it.hasNext()) {
            Map.Entry<Key, Entry> eldest = it.next();
            it.remove();
            totalChars -= eldest.getValue().snapshot().sizeInChars();
            eldest.getKey().state().stored.remove(eldest.getKey().address());
            evictions++;
        }
    }

    /** Caller holds lock. Remove every stored entry of the state. */
    private void purge(State state) {
        for (Address address : state.stored) {
            Entry removed = lru.remove(new Key(state, address));
            if (removed != null) {
                totalChars -= removed.snapshot().sizeInChars();
            }
        }
        state.stored.clear();
    }

    /** Caller holds lock. The state is finished: no entries, nothing more may be stored for it. */
    private void discard(State state) {
        purge(state);
        state.inFlight.clear();
        state.dropped = true;
    }

    private static DecompilationResult decompileWithConfiguredDecompiler(Program program, Function function,
            DecompInterface borrowed) {
        if (borrowed != null) {
            return ConfiguredDecompiler.decompile(borrowed, program, function);
        }
        DecompInterface decompiler = ConfiguredDecompiler.open(program);
        if (decompiler == null) {
            return DecompilationResult.failure(DecompilationResult.FailureKind.INIT_FAILED,
                "Failed to initialize decompiler");
        }
        try {
            return ConfiguredDecompiler.decompile(decompiler, program, function);
        } finally {
            decompiler.dispose();
        }
    }
}
