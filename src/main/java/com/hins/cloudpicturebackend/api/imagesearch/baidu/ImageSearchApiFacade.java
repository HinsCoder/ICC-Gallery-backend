package com.hins.cloudpicturebackend.api.imagesearch.baidu;

import com.hins.cloudpicturebackend.api.imagesearch.baidu.sub.GetImageFirstUrlApi;
import com.hins.cloudpicturebackend.api.imagesearch.baidu.sub.GetImageListApi;
import com.hins.cloudpicturebackend.api.imagesearch.baidu.sub.GetImagePageUrlApi;
import com.hins.cloudpicturebackend.api.imagesearch.baidu.model.ImageSearchResult;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
public class ImageSearchApiFacade {

    /**
     * 搜索图片
     *
     * @param imageUrl
     * @return
     */
    public static List<ImageSearchResult> searchImage(String imageUrl) {
        String imagePageUrl = GetImagePageUrlApi.getImagePageUrl(imageUrl);
        String imageFirstUrl = GetImageFirstUrlApi.getImageFirstUrl(imagePageUrl);
        List<ImageSearchResult> imageList = GetImageListApi.getImageList(imageFirstUrl);
        return imageList;
    }

    public static void main(String[] args) {
        // 百度仅支持png以图搜图
        List<ImageSearchResult> imageList = searchImage("https://cdn.deepseek.com/logo.png");
        System.out.println("结果列表" + imageList);
    }
}