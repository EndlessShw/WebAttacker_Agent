package com.endlessshw.webattacker_agent.rag;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 文档嵌入上传服务
 *
 * 将用户上传的文档切分后嵌入向量存储：
 * - 约束规则文档 → constraintsVectorStore（附带 environment + phase 元数据）
 * - 目标参考文档 → targetDocsVectorStore（附带 taskId + filename 元数据）
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DocumentIngestionService {

    private static final int CHUNK_SIZE = 500;   // 每块最大字符数
    private static final int CHUNK_OVERLAP = 50; // 相邻块重叠字符数

    @Qualifier("constraintsVectorStore")
    private final VectorStore constraintsVectorStore;

    @Qualifier("targetDocsVectorStore")
    private final VectorStore targetDocsVectorStore;

    /**
     * 上传约束规则文档
     *
     * @param file        文档文件（txt / md）
     * @param environment 适用环境：test / staging / production / all
     * @param phase       适用阶段：info_gathering / attack / all
     * @return 生成的文档 ID 列表
     */
    public List<String> ingestConstraintDoc(MultipartFile file, String environment, String phase) throws IOException {
        String content = new String(file.getBytes(), StandardCharsets.UTF_8);
        List<String> chunks = splitIntoChunks(content);

        List<Document> docs = chunks.stream()
                .map(chunk -> {
                    String id = UUID.randomUUID().toString();
                    return new Document(id, chunk, Map.of(
                            "environment", environment != null ? environment : "all",
                            "phase", phase != null ? phase : "all",
                            "filename", file.getOriginalFilename() != null ? file.getOriginalFilename() : "unknown",
                            "type", "constraint"
                    ));
                })
                .toList();

        constraintsVectorStore.add(docs);
        log.info("[DocumentIngestionService] 约束规则文档上传完成: file={}, env={}, phase={}, chunks={}",
                file.getOriginalFilename(), environment, phase, docs.size());

        return docs.stream().map(Document::getId).toList();
    }

    /**
     * 上传目标参考文档
     *
     * @param file   文档文件
     * @param taskId 关联的渗透测试任务 ID
     * @return 生成的文档 ID 列表
     */
    public List<String> ingestTargetDoc(MultipartFile file, String taskId) throws IOException {
        String content = new String(file.getBytes(), StandardCharsets.UTF_8);
        List<String> chunks = splitIntoChunks(content);

        List<Document> docs = chunks.stream()
                .map(chunk -> {
                    String id = UUID.randomUUID().toString();
                    return new Document(id, chunk, Map.of(
                            "taskId", taskId,
                            "filename", file.getOriginalFilename() != null ? file.getOriginalFilename() : "unknown",
                            "type", "target-doc"
                    ));
                })
                .toList();

        targetDocsVectorStore.add(docs);
        log.info("[DocumentIngestionService] 目标文档上传完成: file={}, taskId={}, chunks={}",
                file.getOriginalFilename(), taskId, docs.size());

        return docs.stream().map(Document::getId).toList();
    }

    /**
     * 从约束规则存储中删除文档
     */
    public void deleteConstraintDoc(String documentId) {
        constraintsVectorStore.delete(List.of(documentId));
        log.info("[DocumentIngestionService] 删除约束文档: id={}", documentId);
    }

    /**
     * 从目标文档存储中删除文档
     */
    public void deleteTargetDoc(String documentId) {
        targetDocsVectorStore.delete(List.of(documentId));
        log.info("[DocumentIngestionService] 删除目标文档: id={}", documentId);
    }

    /**
     * 简单的滑动窗口文本切分
     */
    private List<String> splitIntoChunks(String text) {
        if (text.length() <= CHUNK_SIZE) {
            return List.of(text.trim());
        }

        java.util.List<String> chunks = new java.util.ArrayList<>();
        int start = 0;
        while (start < text.length()) {
            int end = Math.min(start + CHUNK_SIZE, text.length());
            // 尝试在句子边界处截断
            if (end < text.length()) {
                int lastNewline = text.lastIndexOf('\n', end);
                int lastPeriod = text.lastIndexOf('。', end);
                int lastDot = text.lastIndexOf(". ", end);
                int boundary = Math.max(lastNewline, Math.max(lastPeriod, lastDot));
                if (boundary > start + CHUNK_SIZE / 2) {
                    end = boundary + 1;
                }
            }
            String chunk = text.substring(start, end).trim();
            if (!chunk.isBlank()) {
                chunks.add(chunk);
            }
            start = end - CHUNK_OVERLAP;
            if (start < 0) start = 0;
            if (start >= text.length()) break;
        }
        return chunks;
    }
}
