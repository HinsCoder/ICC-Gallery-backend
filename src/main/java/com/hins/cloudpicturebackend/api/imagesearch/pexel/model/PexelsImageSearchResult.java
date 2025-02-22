package com.hins.cloudpicturebackend.api.imagesearch.pexel.model;

import lombok.Data;

/**
 * 图片搜索结果
 */
@Data
public class PexelsImageSearchResult {

    /**
     * 缩略图地址
     */
    private String thumbUrl;

    /**
     * 来源地址
     */
    private String fromPexUrl;
}
