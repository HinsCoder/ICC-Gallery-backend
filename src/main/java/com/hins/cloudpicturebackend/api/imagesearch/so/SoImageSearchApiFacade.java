package com.hins.cloudpicturebackend.api.imagesearch.so;

import com.hins.cloudpicturebackend.api.imagesearch.so.model.SoImageSearchResult;
import com.hins.cloudpicturebackend.api.imagesearch.so.sub.GetSoImageListApi;
import com.hins.cloudpicturebackend.api.imagesearch.so.sub.GetSoImageUrlApi;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * 360搜图图片搜索接口（门面模式）
 */
@Slf4j
public class SoImageSearchApiFacade {

    /**
     * 搜索图片
     *
     * @param imageUrl 需要以图搜图的图片地址
     * @param start    开始下表
     * @return 图片搜索结果列表
     */
    public static List<SoImageSearchResult> searchImage(String imageUrl, Integer start) {
        String soImageUrl = GetSoImageUrlApi.getSoImageUrl(imageUrl);
        List<SoImageSearchResult> imageList = GetSoImageListApi.getImageList(soImageUrl, start);
        return imageList;
    }

    public static void main(String[] args) {
        // 测试以图搜图功能
        String imageUrl = "https://cdn.deepseek.com/logo.png";
        List<SoImageSearchResult> resultList = searchImage(imageUrl, 0);
        System.out.println("结果列表" + resultList);
    }
}
