package com.aiburpcopilot.core.verification.mutation.impl;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.verification.model.AttackTask;
import com.aiburpcopilot.core.verification.mutation.IParameterMutator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * 参数修改器注册中心。
 * <p>
 * 管理所有 IParameterMutator 实现，
 * 根据 HTTPContext 和 AttackTask 分发到正确的修改器。
 */
public class ParameterMutatorRegistry {

    private static final Logger log = LoggerFactory.getLogger(ParameterMutatorRegistry.class);

    private final List<IParameterMutator> mutators = new ArrayList<>();

    public ParameterMutatorRegistry() {
        // 按优先级注册（Query 优先于 Body）
        mutators.add(new QueryParameterMutator());
        mutators.add(new JsonBodyMutator());
        mutators.add(new FormBodyMutator());
    }

    /**
     * 查找支持当前上下文的修改器。
     *
     * @param context HTTP 上下文
     * @param task    攻击任务
     * @return 匹配的修改器，或 null（无匹配）
     */
    public IParameterMutator findMutator(HTTPContext context, AttackTask task) {
        String targetParam = task.getParameterName();
        for (IParameterMutator mutator : mutators) {
            if (mutator.supports(context, task)) {
                log.debug("MutatorRegistry: '{}' resolved by {} for param='{}'",
                        mutator.getClass().getSimpleName(), targetParam, targetParam);
                return mutator;
            }
        }
        log.warn("MutatorRegistry: NO mutator found for param='{}' attackType={} "
                        + "| query='{}' | contentType='{}' | bodyLen={} | paramCount={}",
                targetParam, task.getAttackType(),
                context.getQuery() != null ? context.getQuery() : "null",
                context.getContentType() != null ? context.getContentType() : "null",
                context.getRequestBody() != null ? context.getRequestBody().length : 0,
                context.getParameters() != null ? context.getParameters().size() : 0);
        return null;
    }

    /**
     * 注册额外的修改器。
     */
    public void registerMutator(IParameterMutator mutator) {
        mutators.add(mutator);
    }

    /**
     * 获取已注册的修改器数量。
     */
    public int getCount() {
        return mutators.size();
    }
}
