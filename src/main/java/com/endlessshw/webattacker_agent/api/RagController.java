package com.endlessshw.webattacker_agent.api;

import com.endlessshw.webattacker_agent.rag.DocumentIngestionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

/**
 * RAG 文档管理 API
 *
 * 端点：
 *   POST   /api/v1/rag/constraints          上传约束规则文档
 *   POST   /api/v1/rag/target-docs          上传目标参考文档
 *   DELETE /api/v1/rag/constraints/{id}     删除约束规则文档
 *   DELETE /api/v1/rag/target-docs/{id}     删除目标文档
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/rag")
@RequiredArgsConstructor
public class RagController {

    private final DocumentIngestionService documentIngestionService;

    /**
     * POST /api/v1/rag/constraints
     * 上传约束规则文档
     *
     * 表单参数：
     *   file        - 文档文件（txt / md）
     *   environment - 适用环境：test / staging / production / all（默认 all）
     *   phase       - 适用阶段：info_gathering / attack / all（默认 all）
     */
    @PostMapping(value = "/constraints", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> uploadConstraintDoc(
            @RequestPart("file") MultipartFile file,
            @RequestParam(defaultValue = "all") String environment,
            @RequestParam(defaultValue = "all") String phase) {
        try {
            List<String> docIds = documentIngestionService.ingestConstraintDoc(file, environment, phase);
            log.info("[RagController] 约束文档上传: file={}, env={}, phase={}, ids={}",
                    file.getOriginalFilename(), environment, phase, docIds.size());
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "message", "约束规则文档上传成功",
                    "documentIds", docIds,
                    "chunks", docIds.size(),
                    "environment", environment,
                    "phase", phase
            ));
        } catch (Exception e) {
            log.error("[RagController] 约束文档上传失败", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "上传失败: " + e.getMessage()));
        }
    }

    /**
     * POST /api/v1/rag/target-docs
     * 上传目标参考文档
     *
     * 表单参数：
     *   file   - 文档文件
     *   taskId - 关联的渗透测试任务 ID
     */
    @PostMapping(value = "/target-docs", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> uploadTargetDoc(
            @RequestPart("file") MultipartFile file,
            @RequestParam String taskId) {
        if (taskId == null || taskId.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "taskId 不能为空"));
        }
        try {
            List<String> docIds = documentIngestionService.ingestTargetDoc(file, taskId);
            log.info("[RagController] 目标文档上传: file={}, taskId={}, ids={}",
                    file.getOriginalFilename(), taskId, docIds.size());
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "message", "目标文档上传成功",
                    "documentIds", docIds,
                    "chunks", docIds.size(),
                    "taskId", taskId
            ));
        } catch (Exception e) {
            log.error("[RagController] 目标文档上传失败", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "上传失败: " + e.getMessage()));
        }
    }

    /**
     * DELETE /api/v1/rag/constraints/{id}
     * 删除约束规则文档
     */
    @DeleteMapping("/constraints/{id}")
    public ResponseEntity<Map<String, String>> deleteConstraintDoc(@PathVariable("id") String documentId) {
        try {
            documentIngestionService.deleteConstraintDoc(documentId);
            return ResponseEntity.ok(Map.of(
                    "message", "约束文档已删除",
                    "documentId", documentId
            ));
        } catch (Exception e) {
            log.error("[RagController] 约束文档删除失败: id={}", documentId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "删除失败: " + e.getMessage()));
        }
    }

    /**
     * DELETE /api/v1/rag/target-docs/{id}
     * 删除目标文档
     */
    @DeleteMapping("/target-docs/{id}")
    public ResponseEntity<Map<String, String>> deleteTargetDoc(@PathVariable("id") String documentId) {
        try {
            documentIngestionService.deleteTargetDoc(documentId);
            return ResponseEntity.ok(Map.of(
                    "message", "目标文档已删除",
                    "documentId", documentId
            ));
        } catch (Exception e) {
            log.error("[RagController] 目标文档删除失败: id={}", documentId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "删除失败: " + e.getMessage()));
        }
    }
}
