package com.hins.cloudpicturebackend.service;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.util.ObjUtil;
import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.hins.cloudpicturebackend.exception.BusinessException;
import com.hins.cloudpicturebackend.exception.ErrorCode;
import com.hins.cloudpicturebackend.model.dto.user.UserModifyPassWord;
import com.hins.cloudpicturebackend.model.dto.user.UserQueryRequest;
import com.hins.cloudpicturebackend.model.entity.User;
import com.baomidou.mybatisplus.extension.service.IService;
import com.hins.cloudpicturebackend.model.vo.LoginUserVO;
import com.hins.cloudpicturebackend.model.vo.UserVO;
import org.springframework.beans.BeanUtils;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Hins
 * @description 针对表【user(用户)】的数据库操作Service
 * @createDate 2025-02-03 22:39:29
 */
public interface UserService extends IService<User> {

    /**
     * 验证用户输入的验证码是否正确
     *
     * @param userInputCaptcha 用户输入的验证码
     * @param serververifycode 服务器端存储的加密后的验证码
     * @return 如果验证成功返回true，否则返回false
     */
    boolean validateCaptcha(String userInputCaptcha, String serververifycode);
    /**
     * 用户注册
     *
     * @param email 邮箱
     * @param userPassword 用户密码
     * @param checkPassword 校验密码
     * @param code 验证码
     * @return 新用户 id
     */
    long userRegister(String email, String userPassword, String checkPassword, String code);

//    /**
//     * 用户注册
//     *
//     * @param userAccount   用户账户
//     * @param userPassword  用户密码
//     * @param checkPassword 校验密码
//     * @return 新用户 id
//     */
//    @Deprecated
//    long userRegister(String userAccount, String userPassword, String checkPassword);

    /**
     * 用户登录
     *
     * @param accountOrEmail 账号或邮箱
     * @param userPassword 用户密码
     * @param request
     * @return 脱敏后的用户信息
     */
    LoginUserVO userLogin(String accountOrEmail, String userPassword, HttpServletRequest request);

//    /**
//     * 用户登录
//     *
//     * @param userAccount  用户账户
//     * @param userPassword 用户密码
//     * @param request
//     * @return 脱敏后的用户信息
//     */
//    @Deprecated
//    LoginUserVO userLogin(String userAccount, String userPassword, HttpServletRequest request);

    /**
     * 获取加密后的密码
     *
     * @param userPassword 用户密码
     * @return 加密后的密码
     */
    String getEncryptPassword(String userPassword);

    /**
     * 获取当前登录用户
     *
     * @param request
     * @return
     */
    User getLoginUser(HttpServletRequest request);

    /**
     * 获得脱敏后的登录用户信息
     *
     * @param user
     * @return
     */
    LoginUserVO getLoginUserVO(User user);

    /**
     * 判断是否是登录态
     */
    User isLogin(HttpServletRequest request);

    /**
     * 获得脱敏后的用户信息
     *
     * @param user
     * @return
     */
    UserVO getUserVO(User user);

    /**
     * 获得脱敏后的用户信息列表
     *
     * @param userList
     * @return
     */
    List<UserVO> getUserVOList(List<User> userList);


    /**
     * 用户注销
     *
     * @param request
     * @return
     */
    boolean userLogout(HttpServletRequest request);

    /**
     * 获取查询条件
     *
     * @param userQueryRequest
     * @return
     */
    QueryWrapper<User> getQueryWrapper(UserQueryRequest userQueryRequest);

    boolean changePassword(UserModifyPassWord userModifyPassWord, HttpServletRequest request);

    /**
     * 是否为管理员
     *
     * @param user
     * @return
     */
    boolean isAdmin(User user);

    /**
     * 是否为会员
     *
     * @param user
     * @return
     */
    boolean isVip(User user);

    /**
     * 更新用户头像
     *
     * @param multipartFile 头像文件
     * @param id            用户id
     * @param request       HTTP请求
     * @return 头像url
     */
    String updateUserAvatar(MultipartFile multipartFile, Long id, HttpServletRequest request);

    /**
     * 用户兑换会员（会员码兑换）
     */
    boolean exchangeVip(User user, String vipCode);

    /**
     * 获取验证码
     * @return 验证码
     */
    Map<String, String> getCaptcha();

    /**
     * 发送邮箱验证码
     * @param email 邮箱
     * @param type 验证码类型
     * @param request HTTP请求
     */
    void sendEmailCode(String email, String type, HttpServletRequest request);

    /**
     * 修改绑定邮箱
     * @param newEmail 新邮箱
     * @param code 验证码
     * @param request HTTP请求
     * @return 是否修改成功
     */
    boolean changeEmail(String newEmail, String code, HttpServletRequest request);

    /**
     * 重置密码
     * @param email 邮箱
     * @param newPassword 新密码
     * @param checkPassword 确认密码
     * @param code 验证码
     * @return 是否重置成功
     */
    boolean resetPassword(String email, String newPassword, String checkPassword, String code);


    /**
     * 封禁/解禁用户
     * @param userId 目标用户id
     * @param isUnban true-解禁，false-封禁
     * @param admin 执行操作的管理员
     * @return 是否操作成功
     */
    boolean banOrUnbanUser(Long userId, Boolean isUnban, User admin);

    void asyncDeleteUserData(Long id);
}
