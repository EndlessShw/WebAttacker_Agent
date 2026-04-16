package com.endlessshw.webattacker_agent.rag;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * RAG 检索服务
 *
 * 提供两类向量检索：
 * 1. 约束规则检索（constraintsVectorStore）：按 environment + phase 过滤，返回禁止行为列表
 * 2. 目标文档检索（targetDocsVectorStore）：按 taskId 过滤，返回目标相关参考文档
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RagService {

    @Qualifier("constraintsVectorStore")
    private final VectorStore constraintsVectorStore;

    @Qualifier("targetDocsVectorStore")
    private final VectorStore targetDocsVectorStore;

    /**
     * 检索渗透测试约束规则
     *
     * @param environment 环境类型（test / staging / production）
     * @param phase       测试阶段（info_gathering / attack）
     * @return 约束规则文本列表
     */
    public List<String> retrieveConstraints(String environment, String phase) {
        try {
            // 构建过滤条件：environment 匹配（指定环境或 "all"）且 phase 匹配（指定阶段或 "all"）
            FilterExpressionBuilder b = new FilterExpressionBuilder();
            var filter = b.and(
                    b.in("environment", environment, "all"),
                    b.in("phase", phase, "all")
            );

            SearchRequest request = SearchRequest.builder()
                    .query("forbidden operations security constraints " + phase)
                    .topK(10)
                    .filterExpression(filter.build())
                    .build();

            List<Document> docs = constraintsVectorStore.similaritySearch(request);
            List<String> results = docs.stream()
                    .map(Document::getText)
                    .collect(Collectors.toList());

            log.debug("[RagService] 约束规则检索: env={}, phase={}, 找到 {} 条", environment, phase, results.size());
            return results;
        } catch (Exception e) {
            log.warn("[RagService] 约束规则检索失败: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * 检索目标相关文档
     *
     * @param taskId    任务 ID（用于过滤该任务上传的文档）
     * @param targetUrl 目标 URL（用于语义搜索）
     * @return 目标文档内容列表
     */
    public List<String> retrieveTargetDocs(String taskId, String targetUrl) {
        if (taskId == null || taskId.isBlank()) {
            return Collections.emptyList();
        }
        try {
            FilterExpressionBuilder b = new FilterExpressionBuilder();
            var filter = b.eq("taskId", taskId);

            SearchRequest request = SearchRequest.builder()
                    .query("target information " + targetUrl)
                    .topK(5)
                    .filterExpression(filter.build())
                    .build();

            List<Document> docs = targetDocsVectorStore.similaritySearch(request);
            List<String> results = docs.stream()
                    .map(Document::getText)
                    .collect(Collectors.toList());

            log.debug("[RagService] 目标文档检索: taskId={}, 找到 {} 条", taskId, results.size());
            return results;
        } catch (Exception e) {
            log.warn("[RagService] 目标文档检索失败: {}", e.getMessage());
            return Collections.emptyList();
        }
    }
}
