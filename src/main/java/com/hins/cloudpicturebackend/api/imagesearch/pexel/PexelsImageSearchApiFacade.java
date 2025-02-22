package com.hins.cloudpicturebackend.api.imagesearch.pexel;

import com.hins.cloudpicturebackend.api.imagesearch.pexel.model.PexelsImageSearchResult;
import com.hins.cloudpicturebackend.api.imagesearch.pexel.sub.PexelsImageSearch;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class PexelsImageSearchApiFacade {

    private final PexelsImageSearch pexelsImageSearch;

    /**
     * 搜索图片
     *
     * @param query 图片关键字
     * @return 图片搜索结果列表
     */
    public List<PexelsImageSearchResult> searchImage(String query) {
        List<String> imageUrls = pexelsImageSearch.searchPictures(query);
        // 将图片的URL转为ImageSearchResult对象
        return convertToImageSearchResults(imageUrls);
    }


    /**
     * 将图片URL列表转换为ImageSearchResult列表
     *
     * @param imageUrls 图片URL列表
     * @return ImageSearchResult列表
     */
    private List<PexelsImageSearchResult> convertToImageSearchResults(List<String> imageUrls) {
        List<PexelsImageSearchResult> pexelsImageSearchResults = new ArrayList<>();
        for (String url : imageUrls) {
            PexelsImageSearchResult result = new PexelsImageSearchResult();
            // 使用Pexels提供的原图URL作为缩略图
            result.setThumbUrl(url);
            // 这里假设来源地址与缩略图相同
            result.setFromPexUrl(url);
            pexelsImageSearchResults.add(result);
        }
        return pexelsImageSearchResults;
    }
}
