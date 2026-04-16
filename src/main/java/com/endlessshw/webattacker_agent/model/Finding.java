package com.endlessshw.webattacker_agent.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 渗透测试中的单条发现记录
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Finding {

    /** 发现来源阶段：info_gathering / attack */
    private String phase;

    /** 执行的工具或操作名称 */
    private String toolName;

    /** 工具输入 */
    private String toolInput;

    /** 工具输出（截断至合理长度） */
    private String toolOutput;

    /** Agent 对此结果的分析摘要 */
    private String summary;

    /** 发现时间 */
    @Builder.Default
    private Instant timestamp = Instant.now();

    /** 是否为成功的发现（vs 失败/无结果） */
    @Builder.Default
    private boolean success = true;
}
