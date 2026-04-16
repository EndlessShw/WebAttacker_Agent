package com.endlessshw.webattacker_agent.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 渗透测试任务状态（存储于 Redis）
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TaskStatus {

    private String taskId;

    private String targetUrl;

    private String targetEnvironment;

    /** 任务状态枚举 */
    public enum Status {
        PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    }

    @Builder.Default
    private Status status = Status.PENDING;

    /** 当前执行阶段 */
    private String currentPhase;

    /** 已完成的 iteration 轮次 */
    @Builder.Default
    private int iterationCount = 0;

    /** 是否发现有价值的漏洞 */
    @Builder.Default
    private boolean hasFindings = false;

    /** 报告是否已生成 */
    @Builder.Default
    private boolean reportReady = false;

    /** 错误信息（失败时） */
    private String errorMessage;

    @Builder.Default
    private Instant createdAt = Instant.now();

    private Instant completedAt;
}
