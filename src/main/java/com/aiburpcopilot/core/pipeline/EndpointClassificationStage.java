package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.scanner.endpoint.IEndpointClassifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 端点分类 Pipeline Stage。
 * <p>
 * 对 HTTP 上下文进行端点类型分类（ENDPOINT / STATIC_RESOURCE / UNKNOWN）。
 * 分类结果将影响后续 Stage 的执行路径：
 * <ul>
 *   <li>ENDPOINT → 进入 AI 攻击面分析 Stage</li>
 *   <li>STATIC_RESOURCE → 进入静态资源扫描 Stage</li>
 *   <li>UNKNOWN → 不做深入分析</li>
 * </ul>
 */
public class EndpointClassificationStage implements IPipelineStage {

    private static final Logger log = LoggerFactory.getLogger(EndpointClassificationStage.class);

    private final IEndpointClassifier classifier;

    public EndpointClassificationStage(IEndpointClassifier classifier) {
        this.classifier = classifier;
    }

    @Override
    public String getName() {
        return "Endpoint Classification";
    }

    @Override
    public void process(HTTPContext context) {
        classifier.classify(context);
        log.debug("Classified {} as {}", context.getPath(), context.getEndpointType());
    }

    @Override
    public boolean shouldProcess(HTTPContext context) {
        // 所有未分类的请求都需要处理
        return context.getEndpointType() == EndpointType.UNKNOWN
                && context.getAnalysisStatus() != com.aiburpcopilot.core.context.AnalysisStatus.SKIPPED;
    }
}
