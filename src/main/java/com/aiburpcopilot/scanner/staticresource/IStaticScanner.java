package com.aiburpcopilot.scanner.staticresource;

import com.aiburpcopilot.core.context.HTTPContext;

/**
 * 静态资源扫描器接口。
 * <p>
 * 负责扫描静态资源（JS、CSS、HTML 等）中的敏感信息泄露。
 * Phase 1 仅检测和报告，不执行任何攻击行为。
 * <p>
 * 扫描流程：
 * <ol>
 *   <li>响应体规则匹配（正则表达式扫描）</li>
 *   <li>规则命中后调用 AI 复核（去伪存真）</li>
 * </ol>
 */
public interface IStaticScanner {

    /**
     * 对 HTTP 上下文中的响应体执行静态资源扫描。
     *
     * @param context HTTP 上下文（从响应体中提取内容）
     * @return 扫描结果
     */
    StaticScanResult scan(HTTPContext context);

    /**
     * 判断该上下文是否应该执行静态资源扫描。
     *
     * @param context HTTP 上下文
     * @return true 如果可以扫描
     */
    boolean shouldScan(HTTPContext context);
}
