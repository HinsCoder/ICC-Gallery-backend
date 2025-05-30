package com.hins.cloudpicturebackend.service.impl;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.ShearCaptcha;
import cn.hutool.captcha.generator.RandomGenerator;
import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.ObjUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.digest.DigestUtil;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.hins.cloudpicturebackend.constant.CommonValue;
import com.hins.cloudpicturebackend.constant.CrawlerConstant;
import com.hins.cloudpicturebackend.constant.UserConstant;
import com.hins.cloudpicturebackend.exception.BusinessException;
import com.hins.cloudpicturebackend.exception.ErrorCode;
import com.hins.cloudpicturebackend.manager.CrawlerManager;
import com.hins.cloudpicturebackend.manager.auth.StpKit;
import com.hins.cloudpicturebackend.manager.upload.FilePictureUpload;
import com.hins.cloudpicturebackend.manager.upload.PictureUploadTemplate;
import com.hins.cloudpicturebackend.model.dto.file.UploadPictureResult;
import com.hins.cloudpicturebackend.model.dto.user.UserModifyPassWord;
import com.hins.cloudpicturebackend.model.dto.user.UserQueryRequest;
import com.hins.cloudpicturebackend.model.dto.user.VipCode;
import com.hins.cloudpicturebackend.model.entity.Picture;
import com.hins.cloudpicturebackend.model.entity.Space;
import com.hins.cloudpicturebackend.model.entity.User;
import com.hins.cloudpicturebackend.model.enums.UserRoleEnum;
import com.hins.cloudpicturebackend.model.vo.LoginUserVO;
import com.hins.cloudpicturebackend.model.vo.UserVO;
import com.hins.cloudpicturebackend.service.PictureService;
import com.hins.cloudpicturebackend.service.SpaceService;
import com.hins.cloudpicturebackend.service.UserService;
import com.hins.cloudpicturebackend.mapper.UserMapper;
import com.hins.cloudpicturebackend.utils.EmailSenderUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RedissonClient;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.io.ResourceLoader;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.DigestUtils;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * @author Hins
 * @description 针对表【user(用户)】的数据库操作Service实现
 * @createDate 2025-02-03 22:39:29
 */
@Service
@Slf4j
public class UserServiceImpl extends ServiceImpl<UserMapper, User>
        implements UserService {

    @Resource
    private RedissonClient redissonClient;
    @Resource
    private UserMapper userMapper;

    @Resource
    private StringRedisTemplate stringRedisTemplate;

    @Resource
    private EmailSenderUtil emailSenderUtil;

    @Resource
    @Lazy
    private CrawlerManager crawlerManager;

    @Resource
    private FilePictureUpload filePictureUpload;
    @Resource
    @Lazy
    private PictureService pictureService;

    @Resource
    @Lazy
    private SpaceService spaceService;

    @Override
    public boolean validateCaptcha(String userInputCaptcha, String serververifycode) {
        if (userInputCaptcha != null && serververifycode != null) {
            // 使用Hutool对用户输入的验证码进行MD5加密
            String encryptedVerifycode = DigestUtil.md5Hex(userInputCaptcha);
            if (encryptedVerifycode.equals(serververifycode)) {
                return true;
            }
        }
        throw new BusinessException(ErrorCode.PARAMS_ERROR, "验证码错误");
    }

    @Override
    public long userRegister(String email, String userPassword, String checkPassword, String code) {
        // 1. 校验参数
        if (StrUtil.hasBlank(email, userPassword, checkPassword, code)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数为空");
        }
        if (!email.matches("^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$")) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "邮箱格式错误");
        }
        if (userPassword.length() < 8) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "密码过短");
        }
        if (!userPassword.equals(checkPassword)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "两次输入的密码不一致");
        }

        // 校验验证码
        String verifyCodeKey = String.format("email:code:verify:register:%s", email);
        String correctCode = stringRedisTemplate.opsForValue().get(verifyCodeKey);
        if (correctCode == null || !correctCode.equals(code)) {
            // 接口测试时可暂时屏蔽
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "验证码错误或已过期");
        }

        synchronized (email.intern()) {
            // 检查邮箱是否已被注册
            QueryWrapper<User> queryWrapper = new QueryWrapper<>();
            queryWrapper.eq("email", email);
            long count = this.baseMapper.selectCount(queryWrapper);
            if (count > 0) {
                throw new BusinessException(ErrorCode.PARAMS_ERROR, "邮箱已被注册");
            }

            // 检查账号是否已被使用
            String userAccount = email.substring(0, email.indexOf("@")); // 使用邮箱前缀作为账号
            queryWrapper = new QueryWrapper<>();
            queryWrapper.eq("userAccount", userAccount);
            count = this.baseMapper.selectCount(queryWrapper);
            if (count > 0) {
                // 如果账号已存在，则在后面加上随机数
                userAccount = userAccount + RandomUtil.randomNumbers(4);
            }
            String defaultAvatarUrl = String.format(
                    "https://api.dicebear.com/9.x/fun-emoji/svg?seed=%s&backgroundColor=059ff2,71cf62,f6d594,b6e3f4,c0aede,ffd5dc,d1d4f9,ffdfbf&backgroundType=solid,gradientLinear",
                    userAccount
            );

            // 2. 加密
            String encryptPassword = getEncryptPassword(userPassword);
            // 3. 插入数据
            User user = new User();
            user.setUserAccount(userAccount);
            user.setEmail(email);
            user.setUserPassword(encryptPassword);
            user.setUserName(userAccount); // 使用账号作为默认用户名
            user.setUserRole(UserRoleEnum.USER.getValue());
            user.setOutPaintingQuota(1);    // 初始化扩图额度
            user.setUserAvatar(defaultAvatarUrl);
            boolean saveResult = this.save(user);
            if (!saveResult) {
                throw new BusinessException(ErrorCode.SYSTEM_ERROR, "注册失败，数据库错误");
            }
            // 删除验证码
            stringRedisTemplate.delete(verifyCodeKey);
            return user.getId();
        }
    }

//    /**
//     * 用户注册
//     *
//     * @param userAccount   用户账户
//     * @param userPassword  用户密码
//     * @param checkPassword 校验密码
//     * @return 新用户 id
//     */
//    @Deprecated
//    @Override
//    public long userRegister(String userAccount, String userPassword, String checkPassword) {
//        // 1. 校验参数
//        if (StrUtil.hasBlank(userAccount, userPassword, checkPassword)) {
//            throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数为空");
//        }
//        if (userAccount.length() < 4) {
//            throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户账号过短");
//        }
//        if (userPassword.length() < 8 || checkPassword.length() < 8) {
//            throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户密码过短");
//        }
//        if (!userPassword.equals(checkPassword)) {
//            throw new BusinessException(ErrorCode.PARAMS_ERROR, "两次输入的密码不一致");
//        }
//        // 2. 检查用户账号是否和数据库中已有的重复
//        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
//        queryWrapper.eq("userAccount", userAccount);
//        long count = this.baseMapper.selectCount(queryWrapper);
//        if (count > 0) {
//            throw new BusinessException(ErrorCode.PARAMS_ERROR, "账号重复");
//        }
//        // 3. 密码需要加密
//        String encryptPassword = getEncryptPassword(userPassword);
//        // 4. 插入数据到数据库中
//        User user = new User();
//        user.setUserAccount(userAccount);
//        user.setUserPassword(encryptPassword);
//        user.setUserName("无名");
//        user.setUserRole(UserRoleEnum.USER.getValue());
//        boolean saveResult = this.save(user);
//        if (!saveResult) {
//            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "注册失败，数据库错误");
//        }
//        return user.getId();
//    }

    @Override
    public LoginUserVO userLogin(String accountOrEmail, String userPassword, HttpServletRequest request) {
        // 1. 校验
        if (StrUtil.hasBlank(accountOrEmail, userPassword)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数为空");
        }
        if (accountOrEmail.length() < 4) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "账号过短");
        }
        if (userPassword.length() < 8) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "密码过短");
        }
        // 2. 对用户传递的密码进行加密
        String encryptPassword = getEncryptPassword(userPassword);
        // 3. 查询数据库中的用户是否存在
        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("userPassword", encryptPassword)
                .and(wrapper -> wrapper.eq("userAccount", accountOrEmail)
                        .or()
                        .eq("email", accountOrEmail));
        User user = this.baseMapper.selectOne(queryWrapper);
        // 用户不存在，抛异常
        if (user == null) {
            log.info("user login failed, userAccount cannot match userPassword");
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "用户不存在或密码错误");
        }
        // 4. 保存用户的登录态
        request.getSession().setAttribute(UserConstant.USER_LOGIN_STATE, user);
        // 记录用户登录态到 Sa-token，便于空间鉴权时使用，注意保证该用户信息与 SpringSession 中的信息过期时间一致
        StpKit.SPACE.login(user.getId());
        StpKit.SPACE.getSession().set(UserConstant.USER_LOGIN_STATE, user);
        return this.getLoginUserVO(user);
    }

    /**
     * 获取加密后的密码
     *
     * @param userPassword 用户密码
     * @return 加密后的密码
     */
    @Override
    public String getEncryptPassword(String userPassword) {
        // 加盐，混淆密码
        return DigestUtils.md5DigestAsHex((CommonValue.DEFAULT_SALT + userPassword).getBytes());
    }

    @Override
    public User getLoginUser(HttpServletRequest request) {
        try {
            // 优先从 Sa-Token 中获取登录信息
            if (StpKit.SPACE.isLogin()) {
                User user = (User) StpKit.SPACE.getSession().get(UserConstant.USER_LOGIN_STATE);
                if (user != null) {
                    return user;
                }
            }

            // 如果 Sa-Token 中没有，尝试从 Spring Session 中获取（兼容旧代码）
            Object userObj = request.getSession().getAttribute(UserConstant.USER_LOGIN_STATE);
            User currentUser = (User) userObj;
            if (currentUser == null || currentUser.getId() == null) {
                throw new BusinessException(ErrorCode.NOT_LOGIN_ERROR);
            }

            // 从数据库中查询最新的用户信息
            Long userId = currentUser.getId();
            currentUser = this.getById(userId);
            if (currentUser == null) {
                throw new BusinessException(ErrorCode.NOT_LOGIN_ERROR);
            }

            // 更新 Sa-Token 中的用户信息
            StpKit.SPACE.login(userId);
            StpKit.SPACE.getSession().set(UserConstant.USER_LOGIN_STATE, currentUser);

            return currentUser;
        } catch (Exception e) {
            throw new BusinessException(ErrorCode.NOT_LOGIN_ERROR);
        }
    }


    /**
     * 获取脱敏类的用户信息
     *
     * @param user 用户
     * @return 脱敏后的用户信息
     */
    @Override
    public LoginUserVO getLoginUserVO(User user) {
        if (user == null) {
            return null;
        }
        LoginUserVO loginUserVO = new LoginUserVO();
        BeanUtil.copyProperties(user, loginUserVO);
        return loginUserVO;
    }

    @Override
    public User isLogin(HttpServletRequest request) {
        // 判断是否已经登录
        Object userObj = request.getSession().getAttribute(UserConstant.USER_LOGIN_STATE);
        User currentUser = (User) userObj;
        if (currentUser == null || currentUser.getId() == null) {
            return null;
        }
        // 从数据库中查询（追求性能的话可以注释，直接返回上述结果）
        Long userId = currentUser.getId();
        currentUser = this.getById(userId);
        if (currentUser == null) {
            return null;
        }
        return currentUser;
    }

    /**
     * 获得脱敏后的用户信息
     *
     * @param user
     * @return
     */

    @Override
    public UserVO getUserVO(User user) {
        if (user == null) {
            return null;
        }
        UserVO userVO = new UserVO();
        BeanUtils.copyProperties(user, userVO);
        return userVO;
    }

    /**
     * 获得脱敏后的用户信息列表
     *
     * @param userList
     * @return
     */
    @Override
    public List<UserVO> getUserVOList(List<User> userList) {
        if (CollUtil.isEmpty(userList)) {
            return new ArrayList<>();
        }
        return userList.stream()
                .map(this::getUserVO)
                .collect(Collectors.toList());
    }


    @Override
    public boolean userLogout(HttpServletRequest request) {
        // 先判断是否已登录
        Object userObj = request.getSession().getAttribute(UserConstant.USER_LOGIN_STATE);
        if (userObj == null) {
            throw new BusinessException(ErrorCode.OPERATION_ERROR, "未登录");
        }
        // 移除登录态
        request.getSession().removeAttribute(UserConstant.USER_LOGIN_STATE);
        return true;
    }

    @Override
    public QueryWrapper<User> getQueryWrapper(UserQueryRequest userQueryRequest) {
        if (userQueryRequest == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "请求参数为空");
        }
        Long id = userQueryRequest.getId();
        String userAccount = userQueryRequest.getUserAccount();
        String userName = userQueryRequest.getUserName();
        String userProfile = userQueryRequest.getUserProfile();
        String userRole = userQueryRequest.getUserRole();
        String sortField = userQueryRequest.getSortField();
        String sortOrder = userQueryRequest.getSortOrder();
        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq(ObjUtil.isNotNull(id), "id", id);
        queryWrapper.eq(StrUtil.isNotBlank(userRole), "userRole", userRole);
        queryWrapper.like(StrUtil.isNotBlank(userAccount), "userAccount", userAccount);
        queryWrapper.like(StrUtil.isNotBlank(userName), "userName", userName);
        queryWrapper.like(StrUtil.isNotBlank(userProfile), "userProfile", userProfile);
        queryWrapper.orderBy(StrUtil.isNotEmpty(sortField), sortOrder.equals("ascend"), sortField);
        return queryWrapper;
    }

    @Override
    public boolean changePassword(UserModifyPassWord userModifyPassWord, HttpServletRequest request) {
        if (StrUtil.hasBlank(userModifyPassWord.getOldPassword(), userModifyPassWord.getNewPassword(), userModifyPassWord.getCheckPassword())) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数不能为空");
        }
        if (!userModifyPassWord.getNewPassword().equals(userModifyPassWord.getCheckPassword())) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "两次输入的密码不一致");
        }
        if (userModifyPassWord.getNewPassword().length() < 8) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "新密码长度不能小于8位");
        }
        //查询是否有这个用户
        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("id", userModifyPassWord.getId());
        String encryptPassword = getEncryptPassword(userModifyPassWord.getOldPassword());
        queryWrapper.eq("userPassword", encryptPassword);
        User user = userMapper.selectOne(queryWrapper);
        if (user == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "原密码错误");
        }

        user.setUserPassword(getEncryptPassword(userModifyPassWord.getNewPassword()));
        // 更新MySQL
        boolean result = userMapper.updateById(user) > 0;
//        if (result) {
//            // 更新ES
//            EsUser esUser = new EsUser();
//            BeanUtil.copyProperties(user, esUser);
//            esUserDao.save(esUser);
//        }
        return result;
    }

    @Override
    public boolean isAdmin(User user) {
        return user != null && UserRoleEnum.ADMIN.getValue().equals(user.getUserRole());
    }

    @Override
    public boolean isVip(User user) {
        return user != null && UserRoleEnum.VIP.getValue().equals(user.getUserRole());
    }

    @Override
    public boolean isSVip(User user) {
        return user != null && UserRoleEnum.SVIP.getValue().equals(user.getUserRole());
    }

    // region *****兑换会员功能*****
//    // 新增依赖注入
//    @Autowired
//    private ResourceLoader resourceLoader;

    // 文件读写锁（确保并发安全）
    private final ReentrantLock fileLock = new ReentrantLock();

    // VIP 角色常量
    private static final String VIP_ROLE = "vip";

    private static final String SVIP_ROLE = "svip";

    @Value("${vip.gold-vip-code.file-path}")
    private String vipCodeFilePath;

    @Value("${vip.diamond-vip-code.file-path}")
    private String svipCodeFilePath;

    @Data
    private static class ValidationResult {
        private final VipCode vipCode;
        private final UserRoleEnum role;
        private final String filePathUsed;

        public ValidationResult(VipCode vipCode, UserRoleEnum role, String filePathUsed) {
            this.vipCode = vipCode;
            this.role = role;
            this.filePathUsed = filePathUsed;
        }
    }

    /**
     * 兑换会员 (自动判断 VIP 或 SVIP)
     *
     * @param user    当前登录用户
     * @param vipCode 用户输入的兑换码
     * @return 是否成功
     */
    @Override
    @Transactional
    public boolean exchangeVip(User user, String vipCode) {
        // 1. 参数校验
        if (user == null || StrUtil.isBlank(vipCode)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        // 2. 读取、校验兑换码并获取结果 (包含类型和码对象)
        ValidationResult validationResult = validateAndMarkVipCode(vipCode); // 调用修改后的验证方法

        // 3. 更新用户信息 (使用验证结果中的角色)
        updateUserVipInfo(user, validationResult.getVipCode().getCode(), validationResult.getRole()); // 传入角色

        return true;
    }


    /**
     * 校验兑换码（VIP 或 SVIP），标记为已使用，并返回结果信息
     *
     * @param inputCode 用户输入的兑换码
     * @return ValidationResult 包含 VipCode 对象、对应的角色和操作的文件路径
     * @throws BusinessException 如果码无效、已被使用或文件操作失败
     */
    private ValidationResult validateAndMarkVipCode(String inputCode) {
        fileLock.lock(); // 加锁保证文件操作原子性
        try {
            // --- 尝试 VIP 文件 ---
            try {
                JSONArray vipJsonArray = readCodeFile(vipCodeFilePath); // 使用通用读取方法
                // --- 使用你项目中的 VipCode DTO ---
                List<VipCode> vipCodes = JSONUtil.toList(vipJsonArray, com.hins.cloudpicturebackend.model.dto.user.VipCode.class);
                Optional<VipCode> targetVipOpt = vipCodes.stream()
                        .filter(code -> code.getCode().equals(inputCode))
                        .findFirst();

                if (targetVipOpt.isPresent()) {
                    VipCode targetVip = targetVipOpt.get();
                    if (!targetVip.isHasUsed()) {
                        targetVip.setHasUsed(true);
                        writeCodeFile(vipCodeFilePath, JSONUtil.parseArray(vipCodes));
                        log.info("兑换码 {} 在 VIP 文件中找到并标记。", inputCode);
                        return new ValidationResult(targetVip, UserRoleEnum.VIP, vipCodeFilePath);
                    } else {
                        log.warn("尝试兑换的 VIP 码 {} 已被使用。", inputCode);
                        throw new BusinessException(ErrorCode.OPERATION_ERROR, "该兑换码已被使用");
                    }
                }
                log.debug("兑换码 {} 在 VIP 文件中未找到，尝试 SVIP 文件。", inputCode);

            } catch (BusinessException e) {
                if (e.getMessage().contains("已被使用")) throw e;
                log.error("处理 VIP 兑换码文件时出错，将尝试 SVIP 文件: {}", e.getMessage());
            }

            // --- 尝试 SVIP 文件 ---
            try {
                JSONArray svipJsonArray = readCodeFile(svipCodeFilePath);
                // --- 使用你项目中的 VipCode DTO ---
                List<VipCode> svipCodes = JSONUtil.toList(svipJsonArray, com.hins.cloudpicturebackend.model.dto.user.VipCode.class);
                Optional<VipCode> targetSvipOpt = svipCodes.stream()
                        .filter(code -> code.getCode().equals(inputCode))
                        .findFirst();

                if (targetSvipOpt.isPresent()) {
                    VipCode targetSvip = targetSvipOpt.get();
                    if (!targetSvip.isHasUsed()) {
                        targetSvip.setHasUsed(true);
                        writeCodeFile(svipCodeFilePath, JSONUtil.parseArray(svipCodes));
                        log.info("兑换码 {} 在 SVIP 文件中找到并标记。", inputCode);
                        return new ValidationResult(targetSvip, UserRoleEnum.SVIP, svipCodeFilePath);
                    } else {
                        log.warn("尝试兑换的 SVIP 码 {} 已被使用。", inputCode);
                        throw new BusinessException(ErrorCode.OPERATION_ERROR, "该兑换码已被使用");
                    }
                }
                log.warn("兑换码 {} 在 VIP 和 SVIP 文件中均未找到。", inputCode);
                throw new BusinessException(ErrorCode.PARAMS_ERROR, "无效的兑换码");

            } catch (BusinessException e) {
                if (e.getMessage().contains("已被使用")) throw e;
                log.error("处理 SVIP 兑换码文件时出错: {}", e.getMessage());
                throw new BusinessException(ErrorCode.SYSTEM_ERROR, "处理兑换码失败，请稍后重试");
            }

        } finally {
            fileLock.unlock();
        }
    }

    /**
     * 通用读取兑换码文件
     */
    private JSONArray readCodeFile(String filePath) {
        File codeFile = new File(filePath);
        if (!codeFile.exists()) {
            log.error("指定的兑换码文件不存在: {}", filePath);
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "兑换码配置文件丢失: " + codeFile.getName());
        }
        if (!codeFile.isFile()){
            log.error("指定的兑换码文件路径不是一个文件: {}", filePath);
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "兑换码配置路径错误: " + codeFile.getName());
        }
        if (!codeFile.canRead()) {
            log.error("没有读取兑换码文件的权限: {}", filePath);
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "无法读取兑换码配置: " + codeFile.getName());
        }
        try {
            String content = FileUtil.readString(codeFile, StandardCharsets.UTF_8);
            return content.isEmpty() ? new JSONArray() : JSONUtil.parseArray(content);
        } catch (Exception e) {
            log.error("读取或解析外部兑换码文件失败: {}", filePath, e);
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "无法加载兑换码配置");
        }
    }

    /**
     * 通用写入兑换码文件（覆盖写入）
     */
    private void writeCodeFile(String filePath, JSONArray jsonArray) {
        if (jsonArray == null) {
            log.error("尝试将 null 写入兑换码文件: {}", filePath);
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "内部错误：无法保存兑换码状态");
        }
        File codeFile = new File(filePath);
        if (codeFile.exists() && !codeFile.canWrite()) {
            log.error("没有写入兑换码文件的权限: {}", filePath);
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "无法保存兑换码状态更新: " + codeFile.getName());
        }
        File parentDir = codeFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            if (!parentDir.mkdirs()) {
                log.error("无法创建兑换码文件的父目录: {}", parentDir.getAbsolutePath());
                throw new BusinessException(ErrorCode.SYSTEM_ERROR, "无法保存兑换码状态更新");
            }
        }
        try {
            String contentToWrite = jsonArray.toStringPretty();
            Files.write(Paths.get(filePath),
                    contentToWrite.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING);
            log.info("成功更新兑换码文件: {}", filePath);
        } catch (IOException e) {
            log.error("写入兑换码到外部文件失败: {}", filePath, e);
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "无法保存兑换码状态更新");
        }
    }

    // --- updateUserVipInfo 方法保持不变 ---
    /**
     * 更新用户会员信息
     */
    private void updateUserVipInfo(User user, String usedVipCode, UserRoleEnum targetRole) {
        Date expireTime = DateUtil.offsetMonth(new Date(), 12);
        int quota = (targetRole == UserRoleEnum.VIP) ? 50 : (targetRole == UserRoleEnum.SVIP ? 100 : 0);
        if (quota == 0 && (targetRole == UserRoleEnum.VIP || targetRole == UserRoleEnum.SVIP)) {
            log.warn("为角色 {} 设置的额度为 0，请检查逻辑。", targetRole);
        }

        User updateUser = new User();
        updateUser.setId(user.getId());
        updateUser.setVipExpireTime(expireTime);
        updateUser.setVipCode(usedVipCode);
        updateUser.setUserRole(targetRole.getValue());
        updateUser.setOutPaintingQuota(quota);

        boolean updated = this.updateById(updateUser);
        if (!updated) {
            throw new BusinessException(ErrorCode.OPERATION_ERROR, "开通会员失败，更新用户信息时出错");
        }
        log.info("用户 {} 使用兑换码 {} 成功开通/续期 {}, 过期时间: {}, 额度设置为: {}",
                user.getId(), usedVipCode, targetRole.getText(), expireTime, quota);

        // 更新 Session
        try {
            Object sessionObj = StpKit.SPACE.getSession().get(UserConstant.USER_LOGIN_STATE);
            // --- 确保这里的类型是你 Session 中实际存储的用户信息类型 ---
            if (sessionObj instanceof User) { // 或者 LoginUserVO 等
                User sessionUser = (User) sessionObj;
                sessionUser.setUserRole(targetRole.getValue());
                sessionUser.setVipExpireTime(expireTime);
                sessionUser.setOutPaintingQuota(quota);
                StpKit.SPACE.getSession().set(UserConstant.USER_LOGIN_STATE, sessionUser);
                log.info("用户 {} 的 Session 信息已更新。", user.getId());
            } else if (sessionObj != null) {
                log.warn("Session 中的用户信息类型 ({}) 不匹配，无法更新。", sessionObj.getClass().getName());
            } else {
                log.warn("Session 中未找到用户信息，无法更新。");
            }
        } catch (Exception e) {
            log.error("更新用户 Session 信息时出错", e);
        }
    }

    // endregion *****兑换会员功能*****

    @Override
    public void updateOutPaintingQuota(Long userId, int quota) {
        User user = getById(userId);
        if (user != null) {
            user.setOutPaintingQuota(quota);
            updateById(user);
        }
        StpKit.SPACE.getSession().set(UserConstant.USER_LOGIN_STATE, user);
    }

    @Override
    public String updateUserAvatar(MultipartFile multipartFile, Long id, HttpServletRequest request) {
        //判断用户是否存在
        User user = userMapper.selectById(id);
        if (user == null) {
            throw new BusinessException(ErrorCode.NOT_FOUND_ERROR, "用户不存在");
        }
        //判断用户是否登录
        User loginUser = getLoginUser(request);
        if (loginUser == null || !loginUser.getId().equals(id)) {
            throw new BusinessException(ErrorCode.NOT_LOGIN_ERROR, "用户未登录");
        }
        //判断文件是否为空
        if (multipartFile == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "文件不能为空");
        }
        // 判断文件类型
        // 上传图片，得到图片信息
        // 按照用户 id 划分目录
        PictureUploadTemplate pictureUploadTemplate = filePictureUpload;
        String uploadPathPrefix = String.format("public/%s", loginUser.getId());
        UploadPictureResult uploadPictureResult = pictureUploadTemplate.uploadPicture(multipartFile, uploadPathPrefix);
        //更新用户头像
        user.setUserAvatar(uploadPictureResult.getUrl());
        // 更新MySQL
        boolean result = userMapper.updateById(user) > 0;
        return uploadPictureResult.getUrl();
    }

    @Override
    public Map<String, String> getCaptcha() {
        // 仅包含数字的字符集
        String characters = "0123456789";
        // 生成 4 位数字验证码
        RandomGenerator randomGenerator = new RandomGenerator(characters, 4);
        // 定义图片的显示大小，并创建验证码对象
        ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(320, 100, 4, 4);
        shearCaptcha.setGenerator(randomGenerator);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        shearCaptcha.write(outputStream);
        byte[] captchaBytes = outputStream.toByteArray();
        String base64Captcha = Base64.getEncoder().encodeToString(captchaBytes);
        String captchaCode = shearCaptcha.getCode();

        // 使用 Hutool 的 MD5 加密
        String encryptedCaptcha = DigestUtil.md5Hex(captchaCode);

        // 将加密后的验证码和 Base64 编码的图片存储到 Redis 中，设置过期时间为 5 分钟（300 秒）
        stringRedisTemplate.opsForValue().set("captcha:" + encryptedCaptcha, captchaCode, 300, TimeUnit.SECONDS);

        Map<String, String> data = new HashMap<>();
        data.put("base64Captcha", base64Captcha);
        data.put("encryptedCaptcha", encryptedCaptcha);
        return data;
    }

    @Override
    public void sendEmailCode(String email, String type, HttpServletRequest request) {
        if (StrUtil.hasBlank(email, type)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数为空");
        }

        // 检测高频操作
        crawlerManager.detectFrequentRequest(request);

        // 获取客户端IP
        String clientIp = request.getRemoteAddr();
        String ipKey = String.format("email:code:ip:%s", clientIp);
        String emailKey = String.format("email:code:email:%s", email);

        // 检查IP是否频繁请求验证码
        String ipCount = stringRedisTemplate.opsForValue().get(ipKey);
        if (ipCount != null && Integer.parseInt(ipCount) >= 5) {
            throw new BusinessException(ErrorCode.TOO_MANY_REQUEST, "请求验证码过于频繁，请稍后再试");
        }

        // 检查邮箱是否频繁请求验证码
        String emailCount = stringRedisTemplate.opsForValue().get(emailKey);
        if (emailCount != null && Integer.parseInt(emailCount) >= 3) {
            throw new BusinessException(ErrorCode.TOO_MANY_REQUEST, "该邮箱请求验证码过于频繁，请稍后再试");
        }

        // 生成验证码
        String code = RandomUtil.randomNumbers(6);

        // 发送验证码
        try {
            emailSenderUtil.sendEmail(email, code);
        } catch (Exception e) {
            log.error("发送邮件失败", e);
            throw new BusinessException(ErrorCode.OPERATION_ERROR, "发送验证码失败");
        }

        // 记录IP和邮箱的请求次数，设置1小时过期
        stringRedisTemplate.opsForValue().increment(ipKey, 1);
        stringRedisTemplate.expire(ipKey, 1, TimeUnit.HOURS);

        stringRedisTemplate.opsForValue().increment(emailKey, 1);
        stringRedisTemplate.expire(emailKey, 1, TimeUnit.HOURS);

        // 将验证码存入Redis，设置5分钟过期
        String verifyCodeKey = String.format("email:code:verify:%s:%s", type, email);
        stringRedisTemplate.opsForValue().set(verifyCodeKey, code, 5, TimeUnit.MINUTES);
    }

    @Override
    public boolean changeEmail(String newEmail, String code, HttpServletRequest request) {
        // 1. 校验参数
        if (StrUtil.hasBlank(newEmail, code)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数为空");
        }
        if (!newEmail.matches("^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$")) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "邮箱格式错误");
        }

        // 2. 校验验证码
        String verifyCodeKey = String.format("email:code:verify:changeEmail:%s", newEmail);
        String correctCode = stringRedisTemplate.opsForValue().get(verifyCodeKey);
        if (correctCode == null || !correctCode.equals(code)) {
            // 接口测试时可暂时屏蔽
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "验证码错误或已过期");
        }

        // 3. 获取当前登录用户
        User loginUser = getLoginUser(request);

        synchronized (newEmail.intern()) {
            // 4. 检查新邮箱是否已被使用
            QueryWrapper<User> queryWrapper = new QueryWrapper<>();
            queryWrapper.eq("email", newEmail);
            long count = this.baseMapper.selectCount(queryWrapper);
            if (count > 0) {
                throw new BusinessException(ErrorCode.PARAMS_ERROR, "该邮箱已被使用");
            }

            // 5. 更新邮箱
            User user = new User();
            user.setId(loginUser.getId());
            user.setEmail(newEmail);
            boolean result = this.updateById(user);
            if (!result) {
                throw new BusinessException(ErrorCode.SYSTEM_ERROR, "修改邮箱失败");
            }

            // 6. 删除验证码
            stringRedisTemplate.delete(verifyCodeKey);
            return true;
        }
    }

    @Override
    public boolean resetPassword(String email, String newPassword, String checkPassword, String code) {
        // 1. 校验参数
        if (StrUtil.hasBlank(email, newPassword, checkPassword, code)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "参数为空");
        }

        // 2. 校验邮箱格式
        if (!email.matches("^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$")) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "邮箱格式错误");
        }

        // 3. 校验密码
        if (newPassword.length() < 8) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "密码长度不能小于8位");
        }
        if (!newPassword.equals(checkPassword)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "两次输入的密码不一致");
        }

        // 4. 校验验证码
        String verifyCodeKey = String.format("email:code:verify:resetPassword:%s", email);
        String correctCode = stringRedisTemplate.opsForValue().get(verifyCodeKey);
        if (correctCode == null || !correctCode.equals(code)) {
            // 接口测试时可暂时屏蔽
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "验证码错误或已过期");
        }

        // 5. 查询用户是否存在
        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("email", email);
        User user = this.getOne(queryWrapper);
        if (user == null) {
            throw new BusinessException(ErrorCode.NOT_FOUND_ERROR, "用户不存在");
        }

        // 6. 更新密码
        String encryptPassword = getEncryptPassword(newPassword);
        User updateUser = new User();
        updateUser.setId(user.getId());
        updateUser.setUserPassword(encryptPassword);
        boolean result = this.updateById(updateUser);

        if (result) {
            // 7. 删除验证码
            stringRedisTemplate.delete(verifyCodeKey);

        }

        return result;
    }

    @Override
    public boolean banOrUnbanUser(Long userId, Boolean isUnban, User admin) {
        // 1. 校验参数
        if (userId == null || userId <= 0 || isUnban == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }

        // 2. 校验管理员权限
        if (!UserConstant.ADMIN_ROLE.equals(admin.getUserRole())) {
            throw new BusinessException(ErrorCode.NO_AUTH_ERROR, "非管理员不能执行此操作");
        }

        // 3. 获取目标用户信息
        User targetUser = this.getById(userId);
        if (targetUser == null) {
            throw new BusinessException(ErrorCode.NOT_FOUND_ERROR, "用户不存在");
        }

        // 4. 检查当前状态是否需要变更
        boolean isBanned = CrawlerConstant.BAN_ROLE.equals(targetUser.getUserRole());
        if (isUnban == isBanned) {
            // 5. 更新用户角色
            User updateUser = new User();
            updateUser.setId(userId);
            updateUser.setUserRole(isUnban ? UserConstant.DEFAULT_ROLE : CrawlerConstant.BAN_ROLE);
            updateUser.setUpdateTime(new Date());
            boolean result = this.updateById(updateUser);

            if (result) {
                // 6. 记录操作日志
                log.info("管理员[{}]{}用户[{}]",
                        admin.getUserAccount(),
                        isUnban ? "解封" : "封禁",
                        targetUser.getUserAccount());

                // 7. 处理Redis缓存
                String banKey = String.format("user:ban:%d", userId);
                if (isUnban) {
                    stringRedisTemplate.delete(banKey);
                } else {
                    stringRedisTemplate.opsForValue().set(banKey, "1");
                }
            }

            return result;
        } else {
            // 状态已经是目标状态
            String operation = isUnban ? "解封" : "封禁";
            throw new BusinessException(ErrorCode.OPERATION_ERROR,
                    String.format("该用户当前%s不需要%s", isUnban ? "未被封禁" : "已被封禁", operation));
        }
    }

    /**
     * 异步删除用户相关数据
     */
    @Async
    public void asyncDeleteUserData(Long userId) {
        try {
            // 1. 删除用户发布的图片
            QueryWrapper<Picture> pictureQueryWrapper = new QueryWrapper<>();
            pictureQueryWrapper.eq("userId", userId);
            List<Picture> pictureList = pictureService.list(pictureQueryWrapper);
            if (!pictureList.isEmpty()) {
                // 删除数据库记录
                pictureService.remove(pictureQueryWrapper);
            }

            // 2. 删除用户的空间
            QueryWrapper<Space> spaceQueryWrapper = new QueryWrapper<>();
            spaceQueryWrapper.eq("userId", userId);
            List<Space> spaceList = spaceService.list(spaceQueryWrapper);
            if (!spaceList.isEmpty()) {
                // 删除数据库记录
                spaceService.remove(spaceQueryWrapper);
            }

            // 3. 删除用户数据
            this.removeById(userId);

            // 4. 清理相关缓存
            String userKey = String.format("user:ban:%d", userId);
            stringRedisTemplate.delete(userKey);

            log.info("用户相关数据删除完成, userId={}", userId);
        } catch (Exception e) {
            log.error("删除用户相关数据失败, userId={}", userId, e);
            // 这里不抛出异常，因为是异步操作，主流程已经完成
        }
    }
}




