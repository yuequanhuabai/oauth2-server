客户端前端：
资源所有者在客户端点击使用服务端账号进行授权登录;
客户端前端发起get授权请求客户端后端的get授权请求/auth/oauthrize;把code_challenge(hash值),state,client_id,callback_url发送到服务端的后端;

授权服务器后端：
授权服务器后端接受授权请求后，重定向到授权服务端前端的login页面;

授权服务器前端：
资源所有者在授权服务器的前端login页面输入账号密码，点击登录后，请求授权的post接口：/oauth/authorize;

授权服务器后端：
授权服务器后端进行参数验证，生成授权码，通过后通过callback_uri携带授权码重定向回到客户端后端callback接口;

客户端后端：
客户端后端基于授权码,clientI,secret，state,code_verify等再请求授权服务器后端获取access_token;
通过返回后的access_token+正常api访问授权服务器的资源所有者的资源信息;

客户端前端：
基于access_token+api返回的信息做数据回显到前端或前端的操作请求返回;