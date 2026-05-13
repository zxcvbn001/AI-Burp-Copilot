package com.aiburpcopilot.core.verification.registry;

import com.aiburpcopilot.core.context.AttackType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Registry that manages AttackType registrations.
 * <p>
 * Provides a central registry for all supported AttackTypes. The
 * {@link #createDefault()} factory method registers the standard set
 * of attack types used by the verification framework.
 */
public class AttackTypeRegistry {

    private static final Logger log = LoggerFactory.getLogger(AttackTypeRegistry.class);

    private final List<AttackType> registeredTypes = new ArrayList<>();

    /**
     * Register an AttackType.
     *
     * @param attackType the AttackType to register
     */
    public void register(AttackType attackType) {
        if (attackType != null && !registeredTypes.contains(attackType)) {
            registeredTypes.add(attackType);
            log.debug("Registered AttackType: {}", attackType.getDisplayName());
        }
    }

    /**
     * Returns all registered AttackTypes.
     *
     * @return unmodifiable list of registered AttackTypes
     */
    public List<AttackType> getAll() {
        return Collections.unmodifiableList(new ArrayList<>(registeredTypes));
    }

    /**
     * Returns the number of registered AttackTypes.
     */
    public int getCount() {
        return registeredTypes.size();
    }

    /**
     * Creates the default AttackTypeRegistry with all supported attack types.
     * <p>
     * Registers: SQLI, IDOR, SSRF, AUTH, XSS, PATH_TRAVERSAL, OPEN_REDIRECT, SSTI
     */
    public static AttackTypeRegistry createDefault() {
        AttackTypeRegistry registry = new AttackTypeRegistry();
        registry.register(AttackType.SQLI);
        registry.register(AttackType.IDOR);
        registry.register(AttackType.SSRF);
        registry.register(AttackType.AUTH);
        registry.register(AttackType.XSS);
        registry.register(AttackType.PATH_TRAVERSAL);
        registry.register(AttackType.OPEN_REDIRECT);
        registry.register(AttackType.SSTI);
        log.info("AttackTypeRegistry initialized with {} types", registry.getCount());
        return registry;
    }
}
