package com.aiburpcopilot.core.verification.plugins.impl;

import com.aiburpcopilot.core.verification.model.WorkflowDefinition;
import com.aiburpcopilot.core.verification.plugins.IPlugin;
import com.aiburpcopilot.core.verification.workflow.VerificationStep;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Registry that manages all verification plugin registrations.
 * <p>
 * Provides lookup by plugin ID, filtering by enabled state, and
 * aggregate collection of all VerificationSteps and WorkflowDefinitions
 * from registered plugins.
 */
public class PluginRegistry {

    private static final Logger log = LoggerFactory.getLogger(PluginRegistry.class);

    private final Map<String, IPlugin> plugins = new LinkedHashMap<>();

    /**
     * Register a plugin.
     *
     * @param plugin the plugin to register
     */
    public void registerPlugin(IPlugin plugin) {
        if (plugin == null || plugin.getPluginId() == null || plugin.getPluginId().isBlank()) {
            log.warn("Attempted to register null or unnamed plugin");
            return;
        }
        plugins.put(plugin.getPluginId(), plugin);
        log.info("Registered plugin: {} ({})", plugin.getPluginId(), plugin.getName());
    }

    /**
     * Unregister a plugin by its ID.
     *
     * @param pluginId the plugin ID to remove
     */
    public void unregisterPlugin(String pluginId) {
        IPlugin removed = plugins.remove(pluginId);
        if (removed != null) {
            log.info("Unregistered plugin: {} ({})", pluginId, removed.getName());
        } else {
            log.warn("Attempted to unregister unknown plugin: {}", pluginId);
        }
    }

    /**
     * Look up a plugin by its unique ID.
     *
     * @param pluginId the plugin ID
     * @return the plugin, or null if not found
     */
    public IPlugin getPlugin(String pluginId) {
        return plugins.get(pluginId);
    }

    /**
     * Returns all registered plugins.
     *
     * @return unmodifiable list of all plugins
     */
    public List<IPlugin> getAllPlugins() {
        return Collections.unmodifiableList(new ArrayList<>(plugins.values()));
    }

    /**
     * Returns only enabled plugins.
     *
     * @return list of enabled plugins
     */
    public List<IPlugin> getEnabledPlugins() {
        return plugins.values().stream()
                .filter(IPlugin::isEnabled)
                .collect(Collectors.toList());
    }

    /**
     * Collects all VerificationSteps from all enabled plugins.
     *
     * @return list of all VerificationSteps from enabled plugins
     */
    public List<VerificationStep> getAllSteps() {
        List<VerificationStep> allSteps = new ArrayList<>();
        for (IPlugin plugin : getEnabledPlugins()) {
            List<VerificationStep> steps = plugin.getSteps();
            if (steps != null) {
                allSteps.addAll(steps);
            }
        }
        return allSteps;
    }

    /**
     * Collects all WorkflowDefinitions from all enabled plugins.
     *
     * @return list of all WorkflowDefinitions from enabled plugins
     */
    public List<WorkflowDefinition> getAllWorkflows() {
        List<WorkflowDefinition> allWorkflows = new ArrayList<>();
        for (IPlugin plugin : getEnabledPlugins()) {
            WorkflowDefinition workflow = plugin.getWorkflow();
            if (workflow != null) {
                allWorkflows.add(workflow);
            }
        }
        return allWorkflows;
    }

    /**
     * Returns the total number of registered plugins.
     */
    public int getPluginCount() {
        return plugins.size();
    }

    /**
     * Factory method that creates a PluginRegistry pre-populated with
     * all built-in verification plugins.
     *
     * @return a PluginRegistry with SqliPlugin, IdorPlugin, SsrfPlugin, and AuthPlugin registered
     */
    public static PluginRegistry createDefault() {
        PluginRegistry registry = new PluginRegistry();
        registry.registerPlugin(new SqliPlugin());
        registry.registerPlugin(new IdorPlugin());
        registry.registerPlugin(new SsrfPlugin());
        registry.registerPlugin(new AuthPlugin());
        registry.registerPlugin(new XssPlugin());
        registry.registerPlugin(new PathTraversalPlugin());
        log.info("PluginRegistry initialized with {} built-in plugins", registry.getPluginCount());
        return registry;
    }
}
