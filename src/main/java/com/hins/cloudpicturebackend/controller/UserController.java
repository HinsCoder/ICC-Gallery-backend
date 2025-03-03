package com.hins.cloudpicturebackend.controller;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.hins.cloudpicturebackend.annotation.AuthCheck;
import com.hins.cloudpicturebackend.common.BaseResponse;
import com.hins.cloudpicturebackend.common.DeleteRequest;
import com.hins.cloudpicturebackend.common.ResultUtils;
import com.hins.cloudpicturebackend.constant.CommonValue;
import com.hins.cloudpicturebackend.constant.UserConstant;
import com.hins.cloudpicturebackend.exception.BusinessException;
import com.hins.cloudpicturebackend.exception.ErrorCode;
import com.hins.cloudpicturebackend.exception.ThrowUtils;
import com.hins.cloudpicturebackend.model.dto.user.*;
import com.hins.cloudpicturebackend.model.entity.User;
import com.hins.cloudpicturebackend.model.vo.LoginUserVO;
import com.hins.cloudpicturebackend.model.vo.UserVO;
import com.hins.cloudpicturebackend.service.UserService;
import org.springframework.beans.BeanUtils;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {

    @Resource
    private UserService userService;

    /**
     * 获取防刷验证码
     */

    @GetMapping("/getcode")
    public BaseResponse<Map<String, String>> getCode() {
        Map<String, String> captchaData = userService.getCaptcha();
        return ResultUtils.success(captchaData);
    }

    /**
     * 获取邮箱验证码
     */
    @PostMapping("/get_emailcode")
    public BaseResponse<String> getEmailCode(@RequestBody EmailCodeRequest emailCodeRequest, HttpServletRequest request) {
        if (emailCodeRequest == null || StrUtil.hasBlank(emailCodeRequest.getEmail(), emailCodeRequest.getType())) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        userService.sendEmailCode(emailCodeRequest.getEmail(), emailCodeRequest.getType(), request);
        return ResultUtils.success("验证码发送成功");
    }

    /**
     * 修改绑定邮箱
     */
    @PostMapping("/change/email")
    public BaseResponse<Boolean> changeEmail(@RequestBody UserChangeEmailRequest userChangeEmailRequest, HttpServletRequest request) {
        if (userChangeEmailRequest == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        String newEmail = userChangeEmailRequest.getNewEmail();
        String code = userChangeEmailRequest.getCode();
        if (StrUtil.hasBlank(newEmail, code)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        boolean result = userService.changeEmail(newEmail, code, request);
        return ResultUtils.success(result);
    }


    /**
     * 用户注册
     */
    @PostMapping("/register")
    public BaseResponse<Long> userRegister(@RequestBody UserRegisterRequest userRegisterRequest) {
        ThrowUtils.throwIf(userRegisterRequest == null, ErrorCode.PARAMS_ERROR);
        String email = userRegisterRequest.getEmail();
        String userAccount = userRegisterRequest.getUserAccount();
        String userPassword = userRegisterRequest.getUserPassword();
        String checkPassword = userRegisterRequest.getCheckPassword();
        String code = userRegisterRequest.getCode();
        if (StrUtil.hasBlank(email, userPassword, checkPassword, code)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        long result = userService.userRegister(email, userPassword, checkPassword, code);
        return ResultUtils.success(result);
    }

    /**
     *  用户登录
     */
    @PostMapping("/login")
    public BaseResponse<LoginUserVO> userLogin(@RequestBody UserLoginRequest userLoginRequest, HttpServletRequest request) {
        ThrowUtils.throwIf(userLoginRequest == null, ErrorCode.PARAMS_ERROR);
        String accountOrEmail = userLoginRequest.getAccountOrEmail();
        String userPassword = userLoginRequest.getUserPassword();
        String verifyCode = userLoginRequest.getVerifyCode();
        String serververifycode = userLoginRequest.getSerververifycode();
        if (StrUtil.hasBlank(accountOrEmail, userPassword, verifyCode, serververifycode)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        // 校验验证码
        userService.validateCaptcha(verifyCode, serververifycode);
        LoginUserVO loginUserVO = userService.userLogin(accountOrEmail, userPassword, request);
        return ResultUtils.success(loginUserVO);
    }

    /**
     * 获取当前登录用户
     */
    @GetMapping("/get/login")
    public BaseResponse<LoginUserVO> getLoginUser(HttpServletRequest request) {
        User loginUser = userService.getLoginUser(request);
        return ResultUtils.success(userService.getLoginUserVO(loginUser));
    }

    /**
     * 修改密码
     */
    @PostMapping("/changePassword")
    public BaseResponse<Boolean> changePassword(@RequestBody UserModifyPassWord userModifyPassWord, HttpServletRequest request) {
        ThrowUtils.throwIf(userModifyPassWord == null, ErrorCode.PARAMS_ERROR);
        boolean result = userService.changePassword(userModifyPassWord, request);
        return ResultUtils.success(result);
    }

    /**
     * 用户注销
     */
    @PostMapping("/logout")
    public BaseResponse<Boolean> userLogout(HttpServletRequest request) {
        ThrowUtils.throwIf(request == null, ErrorCode.PARAMS_ERROR);
        boolean result = userService.userLogout(request);
        return ResultUtils.success(result);
    }

    /**
     * 创建用户（仅管理员）
     */
    @PostMapping("/add")
    @AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
    public BaseResponse<Long> addUser(@RequestBody UserAddRequest userAddRequest) {
        ThrowUtils.throwIf(userAddRequest == null, ErrorCode.PARAMS_ERROR);
        User user = new User();
        BeanUtils.copyProperties(userAddRequest, user);
        // 默认密码 12345678
        final String DEFAULT_PASSWORD = CommonValue.DEFAULT_PASSWORD;
        String encryptPassword = userService.getEncryptPassword(DEFAULT_PASSWORD);
        user.setUserPassword(encryptPassword);
        // 插入数据库
        boolean result = userService.save(user);
        ThrowUtils.throwIf(!result, ErrorCode.OPERATION_ERROR);
        return ResultUtils.success(user.getId());
    }

    /**
     * 根据 id 获取用户（仅管理员）
     */
    @GetMapping("/get")
    @AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
    public BaseResponse<User> getUserById(long id) {
        ThrowUtils.throwIf(id <= 0, ErrorCode.PARAMS_ERROR);
        User user = userService.getById(id);
        ThrowUtils.throwIf(user == null, ErrorCode.NOT_FOUND_ERROR);
        return ResultUtils.success(user);
    }

    /**
     * 根据 id 获取包装类
     */
    @GetMapping("/get/vo")
    public BaseResponse<UserVO> getUserVOById(long id) {
        BaseResponse<User> response = getUserById(id);
        User user = response.getData();
        return ResultUtils.success(userService.getUserVO(user));
    }

    /**
     * 删除用户（仅管理员）
     */
    @PostMapping("/delete")
    @AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
    public BaseResponse<Boolean> deleteUser(@RequestBody DeleteRequest deleteRequest) {
        if (deleteRequest == null || deleteRequest.getId() <= 0) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        boolean b = userService.removeById(deleteRequest.getId());
        return ResultUtils.success(b);
    }

    /**
     * 更新用户（仅管理员）
     */
    @PostMapping("/update")
    @AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
    public BaseResponse<Boolean> updateUser(@RequestBody UserUpdateRequest userUpdateRequest) {
        if (userUpdateRequest == null || userUpdateRequest.getId() == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        User user = new User();
        BeanUtils.copyProperties(userUpdateRequest, user);
        boolean result = userService.updateById(user);
        ThrowUtils.throwIf(!result, ErrorCode.OPERATION_ERROR);
        return ResultUtils.success(true);
    }

    /**
     * 分页获取用户封装列表（仅管理员）
     *
     * @param userQueryRequest 查询请求参数
     */
    @PostMapping("/list/page/vo")
    @AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
    public BaseResponse<Page<UserVO>> listUserVOByPage(@RequestBody UserQueryRequest userQueryRequest) {
        ThrowUtils.throwIf(userQueryRequest == null, ErrorCode.PARAMS_ERROR);
        long current = userQueryRequest.getCurrent();
        long pageSize = userQueryRequest.getPageSize();
        Page<User> userPage = userService.page(new Page<>(current, pageSize),
                userService.getQueryWrapper(userQueryRequest));
        Page<UserVO> userVOPage = new Page<>(current, pageSize, userPage.getTotal());
        List<UserVO> userVOList = userService.getUserVOList(userPage.getRecords());
        userVOPage.setRecords(userVOList);
        return ResultUtils.success(userVOPage);
    }

    /**
     * 兑换会员
     */
    @PostMapping("/exchange/vip")
    public BaseResponse<Boolean> exchangeVip(@RequestBody VipExchangeRequest vipExchangeRequest,
                                             HttpServletRequest httpServletRequest) {
        ThrowUtils.throwIf(vipExchangeRequest == null, ErrorCode.PARAMS_ERROR);
        String vipCode = vipExchangeRequest.getVipCode();
        User loginUser = userService.getLoginUser(httpServletRequest);
        // 调用 service 层的方法进行会员兑换
        boolean result = userService.exchangeVip(loginUser, vipCode);
        return ResultUtils.success(result);
    }

    /**
     * 忘记密码
     */
    @PostMapping("/reset/password")
    public BaseResponse<Boolean> resetPassword(@RequestBody UserResetPasswordRequest resetPasswordRequest) {
        if (resetPasswordRequest == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        String email = resetPasswordRequest.getEmail();
        String newPassword = resetPasswordRequest.getNewPassword();
        String checkPassword = resetPasswordRequest.getCheckPassword();
        String code = resetPasswordRequest.getCode();

        if (StrUtil.hasBlank(email, newPassword, checkPassword, code)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }

        boolean result = userService.resetPassword(email, newPassword, checkPassword, code);
        return ResultUtils.success(result);
    }

    /**
     * 用户封禁/解禁（仅管理员）
     */
    @PostMapping("/ban")
    @AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
    public BaseResponse<Boolean> banOrUnbanUser(@RequestBody UserUnbanRequest request, HttpServletRequest httpRequest) {
        if (request == null || request.getUserId() == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }

        // 获取管理员信息
        User admin = userService.getLoginUser(httpRequest);

        boolean result = userService.banOrUnbanUser(request.getUserId(), request.getIsUnban(), admin);
        return ResultUtils.success(result);
    }
}
