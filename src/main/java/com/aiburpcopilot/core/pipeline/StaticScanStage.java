package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.scanner.staticresource.IStaticScanner;
import com.aiburpcopilot.scanner.staticresource.StaticScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 静态资源扫描 Pipeline Stage。
 * <p>
 * 仅对 STATIC_RESOURCE 类型的请求执行。
 * 扫描响应体中的敏感信息泄露（硬编码密钥、内网地址等）。
 */
public class StaticScanStage implements IPipelineStage {

    private static final Logger log = LoggerFactory.getLogger(StaticScanStage.class);

    private final IStaticScanner staticScanner;

    public StaticScanStage(IStaticScanner staticScanner) {
        this.staticScanner = staticScanner;
    }

    @Override
    public String getName() {
        return "Static Resource Scan";
    }

    @Override
    public void process(HTTPContext context) {
        StaticScanResult result = staticScanner.scan(context);

        if (result.isHasFindings()) {
            log.info("Static scan found {} issues for: {}",
                    result.getFindings() != null ? result.getFindings().size() : 0,
                    context.getPath());
        }
    }

    @Override
    public boolean shouldProcess(HTTPContext context) {
        return context.getEndpointType() == EndpointType.STATIC_RESOURCE
                && context.getAnalysisStatus() != com.aiburpcopilot.core.context.AnalysisStatus.SKIPPED
                && staticScanner.shouldScan(context);
    }
}
