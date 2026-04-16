package com.endlessshw.webattacker_agent.service.log;

import com.endlessshw.webattacker_agent.model.PentestLog;
import org.springframework.data.domain.Page;

import java.util.List;

/**
 * 日志存储抽象接口
 *
 * 两个实现：
 *   - LocalFileLogStore  (默认，app.log.storage=local)
 *   - ElasticsearchStorageConfig 内联实现 (app.log.storage=elasticsearch)
 */
public interface LogStore {

    /** 异步写入单条日志 */
    void save(PentestLog pentestLog);

    /** 分页查询指定任务的日志 */
    Page<PentestLog> findByTaskId(String taskId, int page, int size);

    /** 查询指定任务的全部日志（按时间升序） */
    List<PentestLog> findAllByTaskId(String taskId);
}
