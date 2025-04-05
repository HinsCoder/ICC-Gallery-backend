package com.hins.cloudpicturebackend.model.dto.user;

import lombok.Data;

@Data
public class ChatRequest {
    private String prompt;
    private String sessionId; // 用于多轮对话
}