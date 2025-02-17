package com.hins.cloudpicturebackend.model.dto.space;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SpaceLevel {

    /**
     * 空间级别值
     */
    private int value;

    /**
     * 级别中文
     */

    private String text;

    /**
     * 最大数量
     */
    private long maxCount;

    /**
     * 最大容量
     */
    private long maxSize;
}
