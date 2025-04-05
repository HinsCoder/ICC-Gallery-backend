package com.hins.cloudpicturebackend.controller;

import com.alibaba.dashscope.app.Application;
import com.alibaba.dashscope.app.ApplicationParam;
import com.alibaba.dashscope.app.ApplicationResult;
import com.alibaba.dashscope.exception.InputRequiredException;
import com.alibaba.dashscope.exception.NoApiKeyException;
import com.google.gson.Gson;
import com.hins.cloudpicturebackend.model.dto.user.ChatRequest;
import io.reactivex.Flowable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 实现 AI 助手聊天接口 (支持多轮对话和流式返回)
 */
@Slf4j
@RestController
@RequestMapping("/chatbot")
public class ChatbotController {

    @Value("${aliYunAi.bailian.apiKey}")
    private String bailianApiKey;

    @Value("${aliYunAi.bailian.appId}")
    private String bailianAppId;

    /**
     * 创建线程池用于处理异步请求
     */
    private final ThreadPoolExecutor executor = new ThreadPoolExecutor(
            2, // 核心线程数
            4, // 最大线程数
            60, TimeUnit.SECONDS, // 空闲线程存活时间
            new LinkedBlockingQueue<>(10), // 工作队列容量
            Executors.defaultThreadFactory(), // 线程工厂
            new ThreadPoolExecutor.AbortPolicy() // 拒绝策略：抛出异常
    );

    /**
     * Gson 实例用于 JSON 序列化 (线程安全，可以复用)
     */
    private final Gson gson = new Gson();

    /**
     * 状态标志位，用于跟踪 ResponseBodyEmitter 是否已完成（包括正常、错误、超时）
     * 使用 volatile 保证多线程间的可见性
     */
    private volatile boolean emitterCompleted = false;


    /**
     * 实现 chat 接口，支持流式返回数据和多轮对话
     *
     * @param chatRequest 包含 prompt 和可选的 sessionId 的请求体 DTO
     * @return ResponseBodyEmitter 用于流式响应 SSE 事件
     */
    @PostMapping("/chat") // 使用 @PostMapping 更符合 RESTful 风格处理创建/执行操作
    public ResponseBodyEmitter streamData(@RequestBody ChatRequest chatRequest) {
        // 设置超时时间
        ResponseBodyEmitter emitter = new ResponseBodyEmitter(180000L);

        // 每次新请求开始时，重置完成状态标志
        emitterCompleted = false;

        // 设置 Emitter 的回调函数
        emitter.onCompletion(() -> {
            emitterCompleted = true; // 标记为已完成
        });

        emitter.onTimeout(() -> {
            emitterCompleted = true; // 超时也标记为已完成处理流程
            // 注意：超时后 emitter 可能不允许再调用 complete/completeWithError
        });

        emitter.onError(throwable -> {
            // 注意：onError 回调会在 completeWithError 调用时触发，或因网络等问题触发
            emitterCompleted = true; // 出错也标记为已完成处理流程
        });

        // 使用线程池异步执行与百炼的交互
        executor.execute(() -> {
            try {
                // 校验 prompt 是否为空
                if (!StringUtils.hasText(chatRequest.getPrompt())) {
                    // 向前端发送一个错误事件
                    if (!isEmitterCompleted(emitter)) { // 发送前检查状态
                        try {
                            emitter.send("id:error\nevent:error\ndata:{\"error\":\"Prompt cannot be empty\"}\n\n",
                                    MediaType.TEXT_EVENT_STREAM); // 使用 MediaType
                            emitter.complete(); // 发送错误后正常完成 Emitter
                        } catch (Exception sendError) {
                            // 即使发送失败，也尝试完成
                            if (!isEmitterCompleted(emitter)) { // 再次检查，以防万一
                                emitter.completeWithError(sendError); // 如果发送失败，以错误状态完成
                            }
                        }
                    }
                    return; // 结束执行
                }
                // 调用核心处理方法
                streamCall(emitter, chatRequest);

            } catch (NoApiKeyException | InputRequiredException e) {
                // 处理百炼 SDK 初始化相关的已知异常
                if (!isEmitterCompleted(emitter)) { // 检查状态后以错误完成
                    emitter.completeWithError(e);
                }
            } catch (Exception e) {
                // 捕获其他所有未预料的异常
                if (!isEmitterCompleted(emitter)) { // 检查状态后以错误完成
                    emitter.completeWithError(e);
                }
            }
        });

        // 返回 emitter 供 Spring MVC 处理
        return emitter;
    }

    /**
     * 调用百炼应用，处理流式响应，并根据请求设置 sessionId (贴近官方 SDK 示例方式)。
     *
     * @param emitter     用于向客户端发送 SSE 事件的 ResponseBodyEmitter
     * @param chatRequest 包含 prompt 和可选 sessionId 的请求 DTO
     * @throws NoApiKeyException    如果 API Key 未配置或无效
     * @throws InputRequiredException 如果必需的输入（如 prompt）缺失
     */
    public void streamCall(ResponseBodyEmitter emitter, ChatRequest chatRequest) throws NoApiKeyException, InputRequiredException {

        // 1. 使用 Builder 构建基础 ApplicationParam 对象 (不在此处设置 sessionId)
        ApplicationParam param = ApplicationParam.builder()
                .appId(bailianAppId)
                .apiKey(bailianApiKey)
                .prompt(chatRequest.getPrompt()) // 设置当前用户输入的 prompt
                .incrementalOutput(true)         // 启用增量流式输出
                .build();                         // 构建对象

        // 2. 如果请求包含 sessionId，则在已构建的 param 对象上调用 setSessionId
        if (StringUtils.hasText(chatRequest.getSessionId())) {
            param.setSessionId(chatRequest.getSessionId()); // 使用 setter 方法设置 sessionId
        } else {
            // 对于新对话，不调用 setSessionId
        }

        // 3. 创建百炼应用实例并开始流式调用
        Application application = new Application();
        Flowable<ApplicationResult> result = application.streamCall(param); // 使用配置好的 param 对象
        AtomicInteger counter = new AtomicInteger(0); // 用于生成 SSE 事件的 ID

        // --- 处理 RxJava Flowable 返回的流式结果 ---
        try {
            // blockingForEach 会阻塞当前线程，直到流完成或出错
            result.blockingForEach(data -> {
                // 检查 emitter 状态，如果已完成（例如客户端断开），则停止处理后续数据
                if (isEmitterCompleted(emitter)) {
                    // 这里无法直接中断 blockingForEach，但可以不再发送数据
                    return; // 跳过本次数据的处理和发送
                }

                int newValue = counter.incrementAndGet(); // 事件 ID 自增
                String jsonData = gson.toJson(data);      // 将百炼返回的 ApplicationResult 对象序列化为 JSON
                // 构造标准 SSE 消息格式 (id, event, data)
                String sseData = String.format("id:%d\nevent:result\ndata:%s\n\n", newValue, jsonData);

                try {
                    // 发送 SSE 事件到客户端
                    emitter.send(sseData.getBytes(StandardCharsets.UTF_8));
                } catch (Exception e) {
                    // 处理发送失败的情况（例如客户端断开连接）
                    // 如果发送失败，通常意味着客户端已断开，应停止后续处理并关闭 Emitter
                    // 抛出异常，让外层 catch 块处理，或者直接在这里关闭 Emitter
                    if (!isEmitterCompleted(emitter)) {
                        emitter.completeWithError(e); // 以错误状态完成
                    }
                    // 抛出运行时异常以尝试中断 blockingForEach（虽然效果不一定理想）
                    throw new RuntimeException("Failed to send data to client, aborting stream processing.", e);
                }

                // 检查百炼返回的数据，看是否是流的结束信号
                if (data.getOutput() != null && "stop".equals(data.getOutput().getFinishReason())) {
                    if (!isEmitterCompleted(emitter)) { // 检查状态后正常完成 Emitter
                        try {
                            emitter.complete();
                        } catch (Exception e) {
                            // 如果 complete() 出错，也要标记为完成
                            emitterCompleted = true;
                        }
                    }
                    // 收到 stop 后，blockingForEach 理论上应该很快会结束
                }
            });
        } catch (Exception e) {
            // 处理 blockingForEach 本身或其内部 lambda 抛出的异常
            // 这包括上面我们为了中断流而抛出的 RuntimeException
            if (!isEmitterCompleted(emitter)) { // 确保在异常时关闭 emitter
                emitter.completeWithError(e);
            }
        } finally {
            // --- 最终保障：无论如何都要确保 emitter 被关闭 ---
            // 这个 finally 块会在 blockingForEach 正常结束、异常退出或中断时执行
            if (!isEmitterCompleted(emitter)) { // 再次检查状态
                try {
                    emitter.complete(); // 尝试最后一次正常关闭
                } catch (Exception finalCompleteError) {
                    // 到这里，很可能连接已经彻底断开，记录日志即可
                    emitterCompleted = true; // 即使关闭失败，也标记为完成，避免死循环或资源泄露
                }
            }
        }
    }

    /**
     * 检查 Emitter 是否已完成 (基于状态标志位)
     * @param emitter ResponseBodyEmitter 实例 (虽然当前实现未使用此参数，保留以备将来扩展)
     * @return 如果 emitter 已标记为完成 (正常/错误/超时)，则返回 true，否则 false
     */
    private boolean isEmitterCompleted(ResponseBodyEmitter emitter) {
        // 直接返回 volatile 标志位的当前状态
        return emitterCompleted;
    }

}