# 城市公交查询系统

## 1. 开发环境配置

> - JDK 8.0.221
>- MySQL 5.0.18
> - Tomcat 8.5.34
>- IntelliJ IDEA

## 2. 技术相关

> - Spring + SpringMVC + MyBatis
> - Jsp + Ajax + Layui + JQuery

## 3. 代码解读

### 3.1 通用功能

#### 3.1.1 登录

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\LoginModel.java
*/

// 登录模块构造方法
package com.bus.controller;
public class LoginModel {
    private Integer id;//登录id
    private String name;//登录名
    private String password;//密码
    private Integer loginType;//登录类型
    public Integer getLoginType() {
        return loginType;
    }
    public void setLoginType(Integer loginType) {
        this.loginType = loginType;
    }
    public Integer getId() {
        return id;
    }
    public void setId(Integer id) {
        this.id = id;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
}
```

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\LoginController.java
*/

@Controller
@RequestMapping("/commonapi")
public class LoginController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    SimpleDateFormat sdf3 = new SimpleDateFormat("yyyyMMddHHmmss");
    @Autowired
    UserInfoMapper userInfoMapper;
    @Autowired
    AdminInfoMapper adminInfoMapper;

    // 系统进入登录页面接口
    @RequestMapping(value = "sys_login")
    public String sys_login(ModelMap modelMap, String msg) {
        modelMap.addAttribute("msg", msg);

        return "sys_login";
    }

    // 系统提交登录验证信息接口
    @RequestMapping("sysSubmit")
    @ResponseBody
    public Object sysSubmit(LoginModel user, String imgCode, ModelMap modelMap,
        HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        Map<String, Object> rs = new HashMap<String, Object>();

        //图片验证码验证,从session中查询验证码并校验
        if ((imgCode == null) || imgCode.trim().equals("")) {
            rs.put("code", 0);
            rs.put("msg","请输入图片验证码");
            return rs;
        }

        if (!imgCode.toLowerCase().equals(request.getSession().getAttribute(CommonVal.code)
                                           .toString().toLowerCase())) {
            rs.put("code", 0);
            rs.put("msg","图片验证码错误");
            return rs;
        }

        if (user.getLoginType() == null) {
            rs.put("code", 0);
            rs.put("msg","请选择登录角色");
            return rs;
        }

        if ((user.getName() == null) || user.getName().equals("")) {
            rs.put("code", 0);
            rs.put("msg","请输入登录名");
            return rs;
        }

        if ((user.getPassword() == null) || user.getPassword().equals("")) {
            rs.put("code", 0);
            rs.put("msg","请输入密码");
            return rs;
        }

        if (user.getLoginType() == 1) {
            //验证管理员账号密码
            AdminInfoExample te = new AdminInfoExample(); 
            AdminInfoExample.Criteria tc = te.createCriteria();
            tc.andNameEqualTo(user.getName());
            tc.andPassWordEqualTo(user.getPassword());
            
            List<AdminInfo> tl = adminInfoMapper.selectByExample(te);
            
            //从数据库中查询不到账号
            if (tl.size() == 0) { 
                rs.put("code", 0);
                rs.put("msg","登录名或密码错误");
                return rs;
            } else {
                LoginModel login = new LoginModel();
                login.setId(tl.get(0).getId());
                login.setLoginType(1);
                login.setName(user.getName());
                //设置登录session,保持会话
                request.getSession().setAttribute(CommonVal.sessionName, login); 
                rs.put("code", 1);
                rs.put("msg","登录成功");
                return rs;
            }
        }

        if (user.getLoginType() == 2) {
            //验证用户账号密码
            UserInfoExample te = new UserInfoExample(); 
            UserInfoExample.Criteria tc = te.createCriteria();
            tc.andNameEqualTo(user.getName());
            tc.andPassWordEqualTo(user.getPassword());

            List<UserInfo> tl = userInfoMapper.selectByExample(te);

            //从数据库中查询不到账号
            if (tl.size() == 0) { 
                rs.put("code", 0);
                rs.put("msg","登录名或密码错误");
                return rs;
            } else {
                LoginModel login = new LoginModel();
                login.setId(tl.get(0).getId());
                login.setLoginType(2);
                login.setName(user.getName());
                //设置登录session,保持会话
                request.getSession().setAttribute(CommonVal.sessionName, login); 
                rs.put("code", 1);
                rs.put("msg","登录成功");
                return rs;
            }
        }

        rs.put("code", 0);
        rs.put("msg","系统出错");
        return rs;
    }
}
```

```java
/**
	过滤器：\ssm_busSystem\src\main\java\com\bus\controller\LoginInterceptor.java
 	过滤器,校验所有需要验证的请求,判断是否有登录,如果未登录,则强制跳转到登录页面,如果已登录,则判断是否正在进行非法请求
*/
public class LoginInterceptor implements HandlerInterceptor {
    public boolean preHandle(HttpServletRequest request,
        HttpServletResponse response, Object handler) throws Exception {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String contextPath2 = requestUri.trim().replaceAll("/", "");

        if (contextPath2.equals("bus_manage_sys") ||
                ((contextPath2.contains("admin") == false) &&
                (contextPath2.contains("user") == false))) {
            return true;
        }

        if (login == null) {
            System.out.println("尚未登录,调到登录页面");
            if (requestUri.contains("/admin/")) {
                //强制跳转到登录页面
                response.sendRedirect(contextPath + "/commonapi/sys_login"); 
                return false;
            }

            if (requestUri.contains("/user/")) {
                //强制跳转到登录页面
                response.sendRedirect(contextPath + "/commonapi/sys_login"); 
                return false;
            }

            response.sendRedirect(contextPath + "/");
            return false;
        } else {
            if (login.getLoginType() == 1) {
                //当前登录角色为管理员,但请求其他角色使用的接口,即盗链,这种需要拦截并提示错误
                if ((requestUri.contains("admin") == false) &&
                     (requestUri.contains("commonapi") == false)) {
                    response.sendRedirect(contextPath + "/commonapi/error?msg=-2");
                    return true;
                }
            }

            if (login.getLoginType() == 2) {
                /当前登录角色为用户,但请求其他角色使用的接口,即盗链,这种需要拦截并提示错误
                if ((requestUri.contains("user") == false) &&
                    (requestUri.contains("commonapi") == false)) { /
                    response.sendRedirect(contextPath + "/commonapi/error?msg=-2");
                    return true;
                }
            }
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request,
                           HttpServletResponse response, Object handler, ModelAndView modelAndView) 		throws Exception {}

    @Override
    public void afterCompletion(HttpServletRequest request,
        					  HttpServletResponse response, Object handler, Exception ex)
    	throws Exception {}
}
```

#### 3.1.2 退出

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\LoginController.java
*/

@Controller
@RequestMapping("/commonapi")
public class LoginController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    SimpleDateFormat sdf3 = new SimpleDateFormat("yyyyMMddHHmmss");
    @Autowired
    UserInfoMapper userInfoMapper;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    
    // 系统退出接口
    @RequestMapping(value = "sys_logout")
    public String sys_logout(ModelMap modelMap, String msg,HttpServletRequest request) {
		request.getSession().removeAttribute(CommonVal.sessionName);
        return "redirect:/commonapi/sys_login";
    }
}
```

#### 3.1.3 修改密码

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\AlterPasswordController.java
*/

@Controller
@RequestMapping("/commonapi/alterPassword")
public class AlterPasswordController {
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    UserInfoMapper userInfoMapper;

    // 进入修改密码页面接口
    @RequestMapping("")
    public Object alterPassword(ModelMap modelMap, HttpServletRequest request,
        HttpServletResponse response) {
        LoginModel user = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        
        if (user == null) {
            return "redirect:/commonapi/login";
        }
        return "alter_password";
    }

    // 提交修改密码请求接口
    @RequestMapping("submit")
    @ResponseBody
    public Object submit(ModelMap modelMap, String password1, String password2,
        String password3, HttpServletRequest request,HttpServletResponse response) {
        Map<String, Object> rs = new HashMap<String, Object>();
        LoginModel user = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);

        if ((password1 == null) || (password2 == null) || (password3 == null)) {
            rs.put("rs", 0);
            rs.put("msg","系统异常");
            return rs;
        }

        if (password2.equals(password3) == false) {
            rs.put("rs", 0);
            rs.put("msg","两次密码输入不一致");
            return rs;
        }

        if (user.getLoginType() == 1) {
            AdminInfo l = adminInfoMapper.selectByPrimaryKey(user.getId());
            //检查该账号原有密码
            if (l.getPassWord().equals(password1) == false) {    
                rs.put("code", 0);
                rs.put("msg","旧密码输入错误");
                return rs;
            }
            //设置为新密码
            l.setPassWord(password2);  
            adminInfoMapper.updateByPrimaryKeySelective(l);
        }

        if (user.getLoginType() == 2) {
            UserInfo l = userInfoMapper.selectByPrimaryKey(user.getId());
		   //检查该账号原有密码
            if (l.getPassWord().equals(password1) == false) {    
                rs.put("code", 0);
                rs.put("msg","旧密码输入错误");
                return rs;
            }
            //设置为新密码
            l.setPassWord(password2);  
            userInfoMapper.updateByPrimaryKeySelective(l);
        }
        
        rs.put("rs", 1);
        rs.put("msg","密码修改成功,会在下次登录生效");
        return rs;
    }
}
```

#### 3.1.4 验证码生成

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\CodeController.java
*/

// 图片验证码生成接口，该接口用来生成一张带有4位随机码的图片
@Controller
public class CodeController {
	@RequestMapping("/commonapi/code") 
    public void getCode(HttpServletRequest req, HttpServletResponse resp) throws IOException { 
		//图片验证码生成器
        ImgRandomCodeUtils rdnu = ImgRandomCodeUtils.Instance();
        // 取得随机字符串放入Session中
		HttpSession session = req.getSession(); 
        //将该验证码存入session中
		session.setAttribute(CommonVal.code, rdnu.getString());
		// 禁止图像缓存。  
        resp.setHeader("Pragma", "no-cache"); 
        resp.setHeader("Cache-Control", "no-cache"); 
        resp.setDateHeader("Expires", 0); 
        resp.setContentType("image/jpeg"); 
        // 将图像输出到Servlet输出流中。  
        ServletOutputStream sos = resp.getOutputStream(); 
        //返回给前台
        ImageIO.write(rdnu.getBuffImg(), "jpeg", sos);
        sos.close(); 
    }
}
```

#### 3.1.5 图片上传

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\ImgUploadController.java
*/

@Controller
@RequestMapping("/commonapi/imgUpload")
public class ImgUploadController {
    //文件上传并生成缩略图
    @RequestMapping(value = "thumb", method = RequestMethod.POST)
    @ResponseBody
    public Object GenerateImage(@RequestParam("file") CommonsMultipartFile file, HttpServletRequest request) throws IOException {
        Map<String, Object> result = new HashMap<String, Object>();
        String realUploadPath = "";
        String uriPath = "";
        if (CommonVal.imgRealPath.equals("") == false) {
            realUploadPath = CommonVal.imgRealPath;
            String[] split = CommonVal.imgRealPath.split("webapps");
            if (split.length > 1) {
                uriPath = split[1];
            }
        } else {
            //使用tomcat文件路径作为上传路径
            realUploadPath = request.getSession().getServletContext().getRealPath("/") + "images";
            uriPath = "ssm_busSystem_war/images";
        }
        //String realUploadPath = "";
        //获取上传后原图的相对地址
        String imageUrl = Upload.uploadImage(file, realUploadPath, uriPath);
        result.put("code", 0);
        result.put("url", "http://" + imageUrl);
        return result;
    }

    @RequestMapping(value = "imgUploadForWangEditor", method = RequestMethod.POST)
    @ResponseBody
    public Map<String, Object> imgUploadForWangEditor(@RequestParam CommonsMultipartFile[] files, HttpServletRequest request) throws UnknownHostException {
        if (files == null) {
            return null;
        }
        List<String> urls = new ArrayList<String>();
        Map<String, Object> result = new HashMap<String, Object>();
        String realUploadPath = "";
        String uriPath = "";
        if (CommonVal.imgRealPath.equals("") == false) {
            realUploadPath = CommonVal.imgRealPath;
            String[] split = CommonVal.imgRealPath.split("webapps");
            if (split.length > 1) {
                uriPath = split[1];
            }
        } else {
            //使用tomcat文件路径作为上传路径
            realUploadPath = request.getSession().getServletContext().getRealPath("/") + "images";
            uriPath = "ssm_busSystem_war/images";
        }
        for (CommonsMultipartFile f : files) {
            String imageUrl;
            try {
                imageUrl = Upload.uploadImage(f, realUploadPath, uriPath);
                urls.add("http://" + imageUrl);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        result.put("data", urls);
        result.put("errno", 0);
        return result;
    }
}
```

### 3.2 管理员

#### 3.2.1 用户管理

##### 查询用户

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\AUserInfoController.java
*/

@Controller
@RequestMapping("/admin/user_info")
public class AUserInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    UserInfoService userInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    UserInfoMapper userInfoMapper;

    // 返回用户列表jsp页面
    @RequestMapping(value = "")
    public String index(ModelMap modelMap, HttpServletRequest request) {
        //获取当前登录账号信息
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        AdminInfo adminInfo = adminInfoMapper.selectByPrimaryKey(login.getId());
        modelMap.addAttribute("user", adminInfo);
        return "admin/user_info/list";
    }

    // 根据查询条件分页查询用户数据,然后返回给前台渲染
    @RequestMapping(value = "queryList")
    @ResponseBody
    public Object toList(UserInfo model, Integer page, String nameOrder,
        HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
		//分页查询数据
        return userInfoService.getDataList(nameOrder, model, page,CommonVal.pageSize, login); 
    }
}
```

##### 删除用户

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\AUserInfoController.java
*/

@Controller
@RequestMapping("/admin/user_info")
public class AUserInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    UserInfoService userInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    UserInfoMapper userInfoMapper;

    // 删除数据接口
    @RequestMapping("del")
    @ResponseBody
    public Object del(Integer id, ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        userInfoService.delete(id);
        rs.put("code", 1);
        rs.put("msg","删除成功");
        return rs;
    }
}
```

#### 3.2.2 车站管理

##### 新增车站

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\AStationInfoController.java
*/

@Controller
@RequestMapping("/admin/station_info")
public class AStationInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    StationInfoService stationInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    StationInfoMapper stationInfoMapper;

    // 进入新增页面
    @RequestMapping("add")
    public String add(ModelMap modelMap, StationInfo model,HttpServletRequest request) {
        //从session中获取当前登录账号
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        modelMap.addAttribute("data", model);
        return "admin/station_info/add_page";
    }

    // 新增提交信息接口
    @RequestMapping("add_submit")
    @ResponseBody
    public Object add_submit(StationInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        //执行添加操作
        String msg = stationInfoService.add(model, login); 

        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","添加成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 查询车站

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\AUserInfoController.java
*/@Controller
@RequestMapping("/admin/station_info")
public class AStationInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    StationInfoService stationInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    StationInfoMapper stationInfoMapper;

    // 返回车站列表jsp页面
    @RequestMapping(value = "")
    public String index(ModelMap modelMap, HttpServletRequest request) {
        //获取当前登录账号信息
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        AdminInfo adminInfo = adminInfoMapper.selectByPrimaryKey(login.getId());
        modelMap.addAttribute("user", adminInfo);
        return "admin/station_info/list";
    }

    // 根据查询条件分页查询车站数据,然后返回给前台渲染
    @RequestMapping(value = "queryList")
    @ResponseBody
    public Object toList(StationInfo model, Integer page,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        return stationInfoService.getDataList(model, page, CommonVal.pageSize,login); //分页查询数据
    }
}
```

##### 修改车站

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\AUserInfoController.java
*/
@Controller
@RequestMapping("/admin/station_info")
public class AStationInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    StationInfoService stationInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    StationInfoMapper stationInfoMapper;

    // 进入修改页面
    @RequestMapping("update")
    public String update(ModelMap modelMap, StationInfo model,HttpServletRequest request) {
        //从session中获取当前登录账号
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        StationInfo data = stationInfoMapper.selectByPrimaryKey(model.getId());
        modelMap.addAttribute("data", data);
        return "admin/station_info/update_page";
    }

    // 修改提交信息接口
    @RequestMapping("update_submit")
    @ResponseBody
    public Object update_submit(StationInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        //执行修改操作
        String msg = stationInfoService.update(model, login); 

        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","修改成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 删除车站

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\AUserInfoController.java
*/
@Controller
@RequestMapping("/admin/station_info")
public class AStationInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    StationInfoService stationInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    StationInfoMapper stationInfoMapper;

    // 删除数据接口
    @RequestMapping("del")
    @ResponseBody
    public Object del(Integer id, ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        stationInfoService.delete(id);
        rs.put("code", 1);
        rs.put("msg","删除成功");
        return rs;
    }
}
```

#### 3.2.3 公交路线

##### 新增公交路线

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABusLineInfoController.java
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABusLineMsgInfoController.java
*/

@Controller
@RequestMapping("/admin/bus_line_info")
public class ABusLineInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    BusLineInfoService busLineInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    BusLineInfoMapper busLineInfoMapper;

    // 进入新增页面
    @RequestMapping("add")
    public String add(ModelMap modelMap, BusLineInfo model,HttpServletRequest request) {
        //从session中获取当前登录账号
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        modelMap.addAttribute("data", model);
        return "admin/bus_line_info/add_page";
    }

    // 新增提交信息接口
    @RequestMapping("add_submit")
    @ResponseBody
    public Object add_submit(BusLineInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        //执行添加操作
        String msg = busLineInfoService.add(model, login); 

        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","添加成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 查询公交路线

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABusLineInfoController.java
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABusLineMsgInfoController.java
*/

@Controller
@RequestMapping("/admin/bus_line_info")
public class ABusLineInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    BusLineInfoService busLineInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    BusLineInfoMapper busLineInfoMapper;

    // 返回公交线路列表jsp页面
    @RequestMapping(value = "")
    public String index(ModelMap modelMap, HttpServletRequest request) {
        //获取当前登录账号信息
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        AdminInfo adminInfo = adminInfoMapper.selectByPrimaryKey(login.getId());
        modelMap.addAttribute("user", adminInfo);
        return "admin/bus_line_info/list";
    }

    @RequestMapping(value = "list")
    public Object list(BusLineInfo model, Integer page,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        //分页查询数据
        return busLineInfoService.getDataList(model, page, CommonVal.pageSize,login); 
    }

    // 根据查询条件分页查询公交线路数据,然后返回给前台渲染
    @RequestMapping(value = "queryList")
    @ResponseBody
    public Object toList(BusLineInfo model, Integer page,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        //分页查询数据
        return busLineInfoService.getDataList(model, page, CommonVal.pageSize,login); 
    }
}
```

##### 修改公交路线

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABusLineInfoController.java
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABusLineMsgInfoController.java
*/

@Controller
@RequestMapping("/admin/bus_line_info")
public class ABusLineInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    BusLineInfoService busLineInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    BusLineInfoMapper busLineInfoMapper;

    // 进入修改页面
    @RequestMapping("update")
    public String update(ModelMap modelMap, BusLineInfo model,HttpServletRequest request) {
        //从session中获取当前登录账号
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        BusLineInfo data = busLineInfoMapper.selectByPrimaryKey(model.getId());
        modelMap.addAttribute("data", data);
        return "admin/bus_line_info/update_page";
    }

    // 修改提交信息接口
    @RequestMapping("update_submit")
    @ResponseBody
    public Object update_submit(BusLineInfo model, ModelMap modelMap,
                                HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        //执行修改操作
        String msg = busLineInfoService.update(model, login); 

        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","修改成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 删除公交路线

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABusLineInfoController.java
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABusLineMsgInfoController.java
*/

@Controller
@RequestMapping("/admin/bus_line_info")
public class ABusLineInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    BusLineInfoService busLineInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    BusLineInfoMapper busLineInfoMapper;

    // 删除数据接口
    @RequestMapping("del")
    @ResponseBody
    public Object del(Integer id, ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        busLineInfoService.delete(id);
        rs.put("code", 1);
        rs.put("msg","删除成功");
        return rs;
    }
}
```

#### 3.2.4 新闻

##### 新增新闻

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ANewsInfoController.java
*/

@Controller
@RequestMapping("/admin/news_info")
public class ANewsInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    NewsInfoService newsInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    NewsInfoMapper newsInfoMapper;

    @RequestMapping(value = "queryDataDetail")
    @ResponseBody
    public Object queryDataDetail(Integer id, HttpServletRequest request) {
        NewsInfo newsInfo = newsInfoMapper.selectByPrimaryKey(id);
        return newsInfo;
    }

    // 进入新增页面
    @RequestMapping("add")
    public String add(ModelMap modelMap, NewsInfo model,HttpServletRequest request) {
	    //从session中获取当前登录账号
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        modelMap.addAttribute("data", model);
        return "admin/news_info/add_page";
    }

    // 新增提交信息接口
    @RequestMapping("add_submit")
    @ResponseBody
    public Object add_submit(NewsInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        //执行添加操作
        String msg = newsInfoService.add(model, login); 
        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","添加成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }

}
```

##### 查询新闻

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ANewsInfoController.java
*/

@Controller
@RequestMapping("/admin/news_info")
public class ANewsInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    NewsInfoService newsInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    NewsInfoMapper newsInfoMapper;

    @RequestMapping(value = "queryDataDetail")
    @ResponseBody
    public Object queryDataDetail(Integer id, HttpServletRequest request) {
        NewsInfo newsInfo = newsInfoMapper.selectByPrimaryKey(id);
        return newsInfo;
    }

    // 返回新闻列表jsp页面
    @RequestMapping(value = "")
    public String index(ModelMap modelMap, HttpServletRequest request) {
        //获取当前登录账号信息
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        AdminInfo adminInfo = adminInfoMapper.selectByPrimaryKey(login.getId());
        modelMap.addAttribute("user", adminInfo);
        return "admin/news_info/list";
    }

    // 根据查询条件分页查询新闻数据,然后返回给前台渲染
    @RequestMapping(value = "queryList")
    @ResponseBody
    public Object toList(NewsInfo model, Integer page, String createTimeOrder,
                         HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        //分页查询数据
        return newsInfoService.getDataList(createTimeOrder, model, page,CommonVal.pageSize, login); 
    }

    // 查看详情接口
    @RequestMapping("detail1")
    public Object detail1(Integer id, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        NewsInfo model = new NewsInfo();
        model.setId(id);
        Map<String, Object> rs = newsInfoService.getDataList(null, model, null,null, login);
        List<Map<String, Object>> tmplist = (List<Map<String, Object>>) rs.get("list");

        if ((tmplist != null) && (tmplist.size() > 0)) {
            modelMap.addAttribute("detail", tmplist.get(0));
        } else {
            modelMap.addAttribute("detail", new HashMap<String, Object>());
        }
        return "admin/news_info/detail";
    }
}
```

##### 修改新闻

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ANewsInfoController.java
*/

@Controller
@RequestMapping("/admin/news_info")
public class ANewsInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    NewsInfoService newsInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    NewsInfoMapper newsInfoMapper;

    @RequestMapping(value = "queryDataDetail")
    @ResponseBody
    public Object queryDataDetail(Integer id, HttpServletRequest request) {
        NewsInfo newsInfo = newsInfoMapper.selectByPrimaryKey(id);
        return newsInfo;
    }

    // 进入修改页面
    @RequestMapping("update")
    public String update(ModelMap modelMap, NewsInfo model,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        NewsInfo data = newsInfoMapper.selectByPrimaryKey(model.getId());

        if (data.getContent() != null) {
            //wangeditor需要过滤掉'符号,否则初始化可能报错
            data.setContent(data.getContent().replaceAll("'", "\\\\'")); 
        }
        modelMap.addAttribute("data", data);
        return "admin/news_info/update_page";
    }

    // 修改提交信息接口
    @RequestMapping("update_submit")
    @ResponseBody
    public Object update_submit(NewsInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        String msg = newsInfoService.update(model, login); 
        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","修改成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 删除新闻

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ANewsInfoController.java
*/

@Controller
@RequestMapping("/admin/news_info")
public class ANewsInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    NewsInfoService newsInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    NewsInfoMapper newsInfoMapper;

    @RequestMapping(value = "queryDataDetail")
    @ResponseBody
    public Object queryDataDetail(Integer id, HttpServletRequest request) {
        NewsInfo newsInfo = newsInfoMapper.selectByPrimaryKey(id);
        return newsInfo;
    }

    // 删除数据接口
    @RequestMapping("del")
    @ResponseBody
    public Object del(Integer id, ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        newsInfoService.delete(id);
        rs.put("code", 1);
        rs.put("msg","删除成功");
        return rs;
    }
}
```

#### 3.2.5 轮播图

##### 新增轮播图

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABannerInfoController.java
*/

@Controller
@RequestMapping("/admin/banner_info")
public class ABannerInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    BannerInfoService bannerInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    BannerInfoMapper bannerInfoMapper;

    // 进入新增页面
    @RequestMapping("add")
    public String add(ModelMap modelMap, BannerInfo model,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        modelMap.addAttribute("data", model);
        return "admin/banner_info/add_page";
    }

    // 新增提交信息接口
    @RequestMapping("add_submit")
    @ResponseBody
    public Object add_submit(BannerInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        String msg = bannerInfoService.add(model, login); //执行添加操作
        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","添加成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 查询轮播图

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABannerInfoController.java
*/

@Controller
@RequestMapping("/admin/banner_info")
public class ABannerInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    BannerInfoService bannerInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    BannerInfoMapper bannerInfoMapper;

    // 返回轮播图列表jsp页面
    @RequestMapping(value = "")
    public String index(ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        AdminInfo adminInfo = adminInfoMapper.selectByPrimaryKey(login.getId());
        modelMap.addAttribute("user", adminInfo);
        return "admin/banner_info/list";
    }

    // 根据查询条件分页查询轮播图数据,然后返回给前台渲染
    @RequestMapping(value = "queryList")
    @ResponseBody
    public Object toList(BannerInfo model, Integer page,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        return bannerInfoService.getDataList(model, page, CommonVal.pageSize,login); 
    }
}
```

##### 修改轮播图

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABannerInfoController.java
*/

@Controller
@RequestMapping("/admin/banner_info")
public class ABannerInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    BannerInfoService bannerInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    BannerInfoMapper bannerInfoMapper;

    // 进入修改页面
    @RequestMapping("update")
    public String update(ModelMap modelMap, BannerInfo model,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        BannerInfo data = bannerInfoMapper.selectByPrimaryKey(model.getId());
        modelMap.addAttribute("data", data);
        return "admin/banner_info/update_page";
    }

    // 修改提交信息接口
    @RequestMapping("update_submit")
    @ResponseBody
    public Object update_submit(BannerInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        String msg = bannerInfoService.update(model, login);
        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","修改成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 删除轮播图

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ABannerInfoController.java
*/

@Controller
@RequestMapping("/admin/banner_info")
public class ABannerInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    BannerInfoService bannerInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    BannerInfoMapper bannerInfoMapper;

    // 删除数据接口
    @RequestMapping("del")
    @ResponseBody
    public Object del(Integer id, ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        bannerInfoService.delete(id);
        rs.put("code", 1);
        rs.put("msg","删除成功");
        return rs;
    }
}
```

#### 3.2.6 用户建议

##### 回复用户建议

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\AAdviceInfoController.java
*/

@Controller
@RequestMapping("/admin/advice_info")
public class AAdviceInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    AdviceInfoService adviceInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    AdviceInfoMapper adviceInfoMapper;

    public void getList(ModelMap modelMap, LoginModel login) { //获取数据列表并返回给前台
        modelMap.addAttribute("isDealList", DataListUtils.getIsDealList()); //返回is_deal数据列表
    }
    
    // 进入回复页面
    @RequestMapping("reply")
    public String reply(ModelMap modelMap, AdviceInfo model,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        getList(modelMap, login); //获取前台需要用到的数据列表并返回给前台
        AdviceInfo data = adviceInfoMapper.selectByPrimaryKey(model.getId());
        modelMap.addAttribute("data", data);
        return "admin/advice_info/reply_page";
    }

    // 回复提交信息接口
    @RequestMapping("reply_submit")
    @ResponseBody
    public Object reply_submit(AdviceInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        String msg = adviceInfoService.reply(model, login); //执行修改操作\
        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","修改成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 查询用户建议

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\AAdviceInfoController.java
*/

@Controller
@RequestMapping("/admin/advice_info")
public class AAdviceInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    AdviceInfoService adviceInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    AdviceInfoMapper adviceInfoMapper;

    public void getList(ModelMap modelMap, LoginModel login) { //获取数据列表并返回给前台
        modelMap.addAttribute("isDealList", DataListUtils.getIsDealList()); //返回is_deal数据列表
    }

    // 返回用户建议列表jsp页面
    @RequestMapping(value = "")
    public String index(ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        AdminInfo adminInfo = adminInfoMapper.selectByPrimaryKey(login.getId());
        modelMap.addAttribute("user", adminInfo);
        getList(modelMap, login); //获取数据列表并返回给前台
        return "admin/advice_info/list";
    }

    // 根据查询条件分页查询用户建议数据,然后返回给前台渲染
    @RequestMapping(value = "queryList")
    @ResponseBody
    public Object toList(AdviceInfo model, Integer page, 
                         String createTimeOrder, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        return adviceInfoService.getDataList(createTimeOrder, model, page,CommonVal.pageSize, login);
    }
}
```

#### 3.2.7 司机

##### 新增司机

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ADriverInfoController.java
*/

@Controller
@RequestMapping("/admin/driver_info")
public class ADriverInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    DriverInfoService driverInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    DriverInfoMapper driverInfoMapper;

    // 进入新增页面
    @RequestMapping("add")
    public String add(ModelMap modelMap, DriverInfo model,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        modelMap.addAttribute("data", model);
        return "admin/driver_info/add_page";
    }

    // 新增提交信息接口
    @RequestMapping("add_submit")
    @ResponseBody
    public Object add_submit(DriverInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        String msg = driverInfoService.add(model, login); //执行添加操作
        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","添加成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 查询司机

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ADriverInfoController.java
*/

@Controller
@RequestMapping("/admin/driver_info")
public class ADriverInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    DriverInfoService driverInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    DriverInfoMapper driverInfoMapper;

    // 返回司机列表jsp页面
    @RequestMapping(value = "")
    public String index(ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        AdminInfo adminInfo = adminInfoMapper.selectByPrimaryKey(login.getId());
        modelMap.addAttribute("user", adminInfo);
        return "admin/driver_info/list";
    }

    // 根据查询条件分页查询司机数据,然后返回给前台渲染
    @RequestMapping(value = "queryList")
    @ResponseBody
    public Object toList(DriverInfo model, Integer page,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        return driverInfoService.getDataList(model, page, CommonVal.pageSize,login); 
    }
}
```

##### 修改司机

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ADriverInfoController.java
*/

@Controller
@RequestMapping("/admin/driver_info")
public class ADriverInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    DriverInfoService driverInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    DriverInfoMapper driverInfoMapper;

    // 进入修改页面
    @RequestMapping("update")
    public String update(ModelMap modelMap, DriverInfo model,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        DriverInfo data = driverInfoMapper.selectByPrimaryKey(model.getId());
        modelMap.addAttribute("data", data);
        return "admin/driver_info/update_page";
    }

    // 修改提交信息接口
    @RequestMapping("update_submit")
    @ResponseBody
    public Object update_submit(DriverInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        String msg = driverInfoService.update(model, login); //执行修改操作
        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","修改成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 删除司机

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\admin\ADriverInfoController.java
*/

@Controller
@RequestMapping("/admin/driver_info")
public class ADriverInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    DriverInfoService driverInfoService;
    @Autowired
    AdminInfoMapper adminInfoMapper;
    @Autowired
    DriverInfoMapper driverInfoMapper;

    // 删除数据接口
    @RequestMapping("del")
    @ResponseBody
    public Object del(Integer id, ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        driverInfoService.delete(id);
        rs.put("code", 1);
        rs.put("msg","删除成功");
        return rs;
    }
}
```

### 3.3 用户

#### 3.3.1 用户注册

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\RegistController.java
*/

@Controller
@RequestMapping("/commonapi")
public class RegistController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    SimpleDateFormat sdf3 = new SimpleDateFormat("yyyyMMddHHmmss");
    @Autowired
    UserInfoMapper userInfoMapper;

    // 系统进入注册页面接口
    @RequestMapping(value = "user_info_regist")
    public String user_info_regist(ModelMap modelMap, String msg) {
        modelMap.addAttribute("msg", msg);
        return "user_info_regist";
    }

    // 提交系统注册信息接口
    @RequestMapping("userInfoRegistSubmit")
    @ResponseBody
    public Object userInfoRegistSubmit(String imgCode, String name, String password, 
                                       ModelMap modelMap, HttpServletRequest request, 
                                       HttpServletResponse response) {
        Map<String, Object> rs = new HashMap<String, Object>();
        HttpSession session = request.getSession();
        if ((imgCode != null) && !imgCode.toLowerCase()
            .equals(request.getSession()
            .getAttribute(CommonVal.code)
            .toString().toLowerCase())) {
            
            rs.put("code", 0);
            rs.put("msg","图片验证码错误");
            return rs;
        }

        if (name != null) {
            UserInfoExample te = new UserInfoExample();
            UserInfoExample.Criteria tc = te.createCriteria();
            tc.andNameEqualTo(name);
            int count = (int) userInfoMapper.countByExample(te);
            if (count > 0) {
                rs.put("code", 0);
                rs.put("msg","该账号已被注册,请用该账号登录");
                return rs;
            }
        }
        UserInfo model = new UserInfo();
        model.setName(name);
        model.setPassWord(password);
        model.setCreateTime(sdf1.format(new Date())); //当前时间格式
        userInfoMapper.insertSelective(model); //注册成功,插入该账号进数据库,并返回提示
        rs.put("code", 1);
        rs.put("msg","注册成功,请使用该账号密码登录");
        return rs;
    }
}
```

#### 3.3.2 搜索路线

##### 模糊搜索

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\index\IndexBusLineInfoListController.java
*/

@Controller
@RequestMapping("/commonapi/index")
public class IndexBusLineInfoListController {
    @Autowired
    static
    BusLineInfoMapper busLineInfoMapper;
    @Autowired
    static
    BusLineMsgInfoMapper busLineMsgInfoMapper;
    @Autowired
    static
    StationInfoMapper stationInfoMapper;
    @Autowired
    BannerInfoMapper bannerInfoMapper;

    // 进入搜索列表接口
    @RequestMapping(value = "")
    public String index(ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        modelMap.addAttribute("login", login);
        BannerInfoExample be = new BannerInfoExample();
        be.setOrderByClause("id desc");
        be.setPageRows(0);
        be.setStartRow(4);
        List<BannerInfo> bl = bannerInfoMapper.selectByExample(be);
        modelMap.addAttribute("bl", bl);
        return "index/bus_line_info_list";
    }

    @RequestMapping(value = "search")
    @ResponseBody
    public Object search(String searchWord, Integer page,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        int pageSize = 8;
        if (page == null) {
            page = 1;
        }

        BusLineInfoExample te = new BusLineInfoExample();
        BusLineInfoExample.Criteria tc = te.createCriteria();

        if ((searchWord != null) && (searchWord.trim().equals("") == false)) {
            tc.andLineNameLike("%" + searchWord + "%");
        }

        int count = (int) busLineInfoMapper.countByExample(te);
        int totalPage = 0;

        if ((count > 0) && ((count % pageSize) == 0)) {
            totalPage = count / pageSize;
        } else {
            totalPage = (count / pageSize) + 1;
        }

        te.setPageRows(pageSize);
        te.setStartRow((page - 1) * pageSize);

        List<BusLineInfo> tl = busLineInfoMapper.selectByExample(te);
        List<Map<String, Object>> list = new ArrayList<Map<String, Object>>();

        for (BusLineInfo t : tl) {
            Map<String, Object> map = new HashMap<String, Object>();
            map.put("t", t);
            BusLineMsgInfoExample be2 = new BusLineMsgInfoExample();
            BusLineMsgInfoExample.Criteria bc2 = be2.createCriteria();
            bc2.andLineIdEqualTo(t.getId());
            be2.setOrderByClause("no asc");//根据编号排序
            List<BusLineMsgInfo> bl2 = busLineMsgInfoMapper.selectByExample(be2);
            for (BusLineMsgInfo b2 : bl2) {
                StationInfo s = stationInfoMapper.selectByPrimaryKey(b2.getStationId());
                b2.setCreateTime(s.getStationName());
            }
            map.put("bl2", bl2);
            list.add(map);
        }

        Map<String, Object> rs = new HashMap<String, Object>();
        rs.put("data", list);
        rs.put("count", count);
        rs.put("totalPage", totalPage);
        rs.put("pageSize", pageSize);

        return rs;
    }
}
```

#### 3.3.3 换站查询

##### 精准查询

```javascript
/** 
	\ssm_busSystem\src\main\webapp\WEB-INF\views\index\cal_line.jsp
*/

function ajaxList(page) {
        //1.默认搜索，2.排序按钮
        var startId = $("#startId").val();
        var endId = $("#endId").val();
        $.ajax({
            type: 'post',
            url: "${pageContext.request.contextPath}/commonapi/index/cal/submitCal",
            data: {
                "startId": startId,
                "endId": endId
            },
            success: function (result) {
                var rows = result;//得到数据列
                var html = '';
                for (var i = 0; i < rows.length; i++) {
                    var list = rows[i].list;
                    var msg = '';
                    for (var j = 0; j < list.length; j++) {
                        msg += list[j].stationName + '-->';
                    }
                    if (msg != '') {
                        msg = msg.substring(0, msg.length - 3);
                    }
                    html += ' <li>';
                    html += '<h2>';
                    html += ' <a href="#">' + msg + '</a>';
                    html += ' </h2>';
                    html += ' <div class="fly-list-info">';
                    html += '<span>换乘次数：' + rows[i].changeTimes + '</span>';
                    html += '<span>费用：' + rows[i].totalPrice + '</span>';
                    html += '<span>预计时间：' + rows[i].costTime + '分钟</span>';
                    html += '</div>';
                    html += ' <div class="fly-list-badge">';
                    html += ' </div>';
                    html += '</li>';
                }
                if (rows.length == 0) {
                    html += ' <div class="fly-none">没有相关数据</div>';
                }
                $("#dataList").html(html);
            }
        });
    }
```

#### 3.3.4 建议

##### 新增建议

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\user\UUserInfoController.java
*/

@Controller
@RequestMapping("/user/advice_info")
public class UAdviceInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    AdviceInfoService adviceInfoService;
    @Autowired
    UserInfoMapper userInfoMapper;
    @Autowired
    AdviceInfoMapper adviceInfoMapper;

    public void getList(ModelMap modelMap, LoginModel login) { //获取数据列表并返回给前台
        modelMap.addAttribute("isDealList", DataListUtils.getIsDealList()); //返回is_deal数据列表
    }

    // 进入我要反馈页面
    @RequestMapping("add")
    public String add(ModelMap modelMap, AdviceInfo model,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        getList(modelMap, login); //获取前台需要用到的数据列表并返回给前台
        modelMap.addAttribute("data", model);
        return "user/advice_info/add_page";
    }

    // 我要反馈提交信息接口
    @RequestMapping("add_submit")
    @ResponseBody
    public Object add_submit(AdviceInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        String msg = adviceInfoService.add(model, login); //执行添加操作
        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","添加成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 查询建议

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\user\UUserInfoController.java
*/

@Controller
@RequestMapping("/user/advice_info")
public class UAdviceInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    AdviceInfoService adviceInfoService;
    @Autowired
    UserInfoMapper userInfoMapper;
    @Autowired
    AdviceInfoMapper adviceInfoMapper;

    public void getList(ModelMap modelMap, LoginModel login) { //获取数据列表并返回给前台
        modelMap.addAttribute("isDealList", DataListUtils.getIsDealList()); //返回is_deal数据列表
    }

    // 返回用户建议列表jsp页面
    @RequestMapping(value = "")
    public String index(ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        UserInfo userInfo = userInfoMapper.selectByPrimaryKey(login.getId());
        modelMap.addAttribute("user", userInfo);
        getList(modelMap, login); //获取数据列表并返回给前台
        return "user/advice_info/list";
    }

    // 根据查询条件分页查询用户建议数据,然后返回给前台渲染
    @RequestMapping(value = "queryList")
    @ResponseBody
    public Object toList(AdviceInfo model, Integer page,
                         String createTimeOrder, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        model.setUserId(login.getId()); //反馈用户等于当前登录id
        return adviceInfoService.getDataList(createTimeOrder, model, page,CommonVal.pageSize, login);
    }
}
```

##### 修改建议

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\user\UUserInfoController.java
*/

@Controller
@RequestMapping("/user/advice_info")
public class UAdviceInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    AdviceInfoService adviceInfoService;
    @Autowired
    UserInfoMapper userInfoMapper;
    @Autowired
    AdviceInfoMapper adviceInfoMapper;

    public void getList(ModelMap modelMap, LoginModel login) { //获取数据列表并返回给前台
        modelMap.addAttribute("isDealList", DataListUtils.getIsDealList()); //返回is_deal数据列表
    }

    // 进入修改页面
    @RequestMapping("update")
    public String update(ModelMap modelMap, AdviceInfo model,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        getList(modelMap, login); //获取前台需要用到的数据列表并返回给前台
        AdviceInfo data = adviceInfoMapper.selectByPrimaryKey(model.getId());
        modelMap.addAttribute("data", data);
        return "user/advice_info/update_page";
    }

    // 修改提交信息接口
    @RequestMapping("update_submit")
    @ResponseBody
    public Object update_submit(AdviceInfo model, ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        String msg = adviceInfoService.update(model, login); //执行修改操作
        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","修改成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

##### 删除建议

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\user\UUserInfoController.java
*/

@Controller
@RequestMapping("/user/advice_info")
public class UAdviceInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    AdviceInfoService adviceInfoService;
    @Autowired
    UserInfoMapper userInfoMapper;
    @Autowired
    AdviceInfoMapper adviceInfoMapper;

    public void getList(ModelMap modelMap, LoginModel login) { //获取数据列表并返回给前台
        modelMap.addAttribute("isDealList", DataListUtils.getIsDealList()); //返回is_deal数据列表
    }

    // 删除数据接口
    @RequestMapping("del")
    @ResponseBody
    public Object del(Integer id, ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        adviceInfoService.delete(id);
        rs.put("code", 1);
        rs.put("msg","删除成功");
        return rs;
    }
}
```

#### 3.3.5 个人信息

##### 修改个人信息

```java
/** 
	\ssm_busSystem\src\main\java\com\bus\controller\user\UUserInfoController.java
*/

@Controller
@RequestMapping("/user/user_info")
public class UUserInfoController {
    SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
    @Autowired
    UserInfoService userInfoService;
    @Autowired
    UserInfoMapper userInfoMapper;

    // 进入用户详情页
    @RequestMapping("detail")
    public Object detail(ModelMap modelMap, HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        UserInfo model = new UserInfo();
        model.setId(login.getId());
        Map<String, Object> rs = userInfoService.getDataList(null, model, null, null, login);
        List<Map<String, Object>> tmplist = (List<Map<String, Object>>) rs.get("list");
        if ((tmplist != null) && (tmplist.size() > 0)) {
            modelMap.addAttribute("detail", tmplist.get(0));
        } else {
            modelMap.addAttribute("detail", new HashMap<String, Object>());
        }
        return "user/personal";
    }

    // 修改页面
    @RequestMapping("update")
    public String update(ModelMap modelMap, UserInfo model,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName); 
        UserInfo data = userInfoMapper.selectByPrimaryKey(model.getId());
        modelMap.addAttribute("data", data);
        return "user/user_info/update_page";
    }

    // 提交信息接口
    @RequestMapping("update_submit")
    @ResponseBody
    public Object update_submit(UserInfo model, ModelMap modelMap,HttpServletRequest request) {
        LoginModel login = (LoginModel) request.getSession().getAttribute(CommonVal.sessionName);
        Map<String, Object> rs = new HashMap<String, Object>();
        String msg = userInfoService.update(model, login); //执行修改操作
        if (msg.equals("")) {
            rs.put("code", 1);
            rs.put("msg","修改成功");
            return rs;
        }
        rs.put("code", 0);
        rs.put("msg", msg);
        return rs;
    }
}
```

## 4.数据库相关

### 4.1 创建数据库文件

> \ssm_busSystem\src\main\resources\bus_manage_sys.sql  

#### 4.2 数据库连接配置文件

> \ssm_busSystem\src\main\resources\config.properties
