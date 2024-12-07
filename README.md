# Deploy Trojan using a Serverless CF-Workers & Pages

🇮🇷 [Persian](README.fa.md)  
🇹🇷 [Turkish](README.tr.md)  
🇬🇧 [English](README.md)  
🇩🇪 [Germany](README.de.md)  


This is a script based on the Cloudflare Worker platform. Based on the original version, it is modified to display Trojan configuration information and convert it into subscription content. Using this script, you can easily convert Trojan configuration information to tools such as Clash or Singbox using online configuration.  

[TG Channel](https://t.me/F_NiREvil)

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)
## Table of Contents
  - [Workers deployment method](#Workers-deployment-method)
  - [Pages deployment method](#Pages-deployment-method)
  - [proxyIP](#proxyIP)
  - [Environment Variable description](#Environment-variables-description)
  - [Video tutorials](#Video-tutorials)
![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)


<details>
<summary> Use </summary>

  - This project is designed and developed for learning, research and safety testing purposes only. It aims to provide security researchers, academics and technology enthusiasts with a tool to understand and practice network communication technology.
</details>

<details>
<summary> Legality </summary>
  
  - Users must comply with local laws and regulations when downloading and using this project.
  - Users are responsible for ensuring that their actions comply with the laws, regulations and other applicable requirements of their region

</details>


<details>
<summary> Risk warning </summary>
  - Avoid leaking node configuration information by submitting false node configurations to the subscription service 
</details>



## Workers deployment method

1.  Deploy Cloudflare Worker:
    - Create a new Worker in the Cloudflare Worker console.
    - Will [worker.js](_worker.js) Paste the contents into the Worker editor.
    - Change line 3 `password` Modify it to your own **password**
  
    - Alternatively, you can click the button below to deploy directly.

   [![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/NiREvil/Trauma)

3.  Add preferred route:
    - Give `addresses` Add the preferred domain name/preferred clean IP according to the format. If there is no port number, the default TLS port is 443, and the # sign is the remark alias, for example:
        ```js
        let addresses = [
        // any Domain or clean IPv4/IPv6 addresses from cloudflare is usable, no sweat.
        'cdnjs.com:443#N1',
        'www.wto.org:2053#N2',
        'sky.rethinkdns.com#N3',
        'creativecommons.org#N4',
        '[2606:4700:310c::ac42:2c39]#N5 √IPv6',
      ];
        ```

4.  Access subscription content:
    - access `https://[YOUR-WORKERS-URL]/[password]` Get subscription content.
    - For example `https://vless.trauma.workers.dev/auto` This is your universal adaptive subscription address.
    - For example `https://vless.trauma.workers.dev/auto?sub` Base64 subscription format, suitable for PassWall, SSR+, etc.
    - For example `https://vless.trauma.workers.dev/auto?clash` Clash subscription format, suitable for OpenClash, etc.
    - For example `https://vless.trauma.workers.dev/auto?sb` singbox subscription format, suitable for singbox, etc.

5.  Bind a custom domain to workers:
    - In the workers console `trigger` tab, click below `Add a custom domain` 。
    - Fill in the secondary domain name that you have transferred to the CloudFlare domain name resolution service, for example: `vless.trauma.com` After click `Add a custom domain` , just wait for the certificate to take effect.

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)
## Pages deployment method

1. Deploy Cloudflare Pages:
    - Fork [this project on Github](https://github.com/NiREvil/Trauma/fork)
    - Select in the Cloudflare Pages console `Connected to Git` After that, select `trauma` Click after the item `Start setting up`。
    - exist `Setting up build and deployment` At the bottom of the page, select `Environment variables (advanced)` merge later [Add variables](#Environment-variables-description),
     - Fill in the variable name **PASSWORD** , the value is your password, then click `Save and deploy` That’s it.
  
2. Add preferred route:
   - Add variables `ADD` Local static preferred line, if there is no port number, the default TLS port is 443, and the # number is followed by a remark alias, for example:
     ```js
     discord.com#You can just put the domain name as follows
     www.speedtest.net:443#N1
     speed.cloudflare.com#N2
     zula.ir#N3
     creativecommons.org:2053#N4
     sky.rethinkdns.com#N5
     104.17.152.41#IPv4 is available
     [2606:4700:310c::ac42:2c39]#also IPv6
     ```

3. Access subscription content:
    - access `https://[YOUR-PAGES-URL]/[password]` Subscription content is available.
    - For example `https://trauma.pages.dev/auto` This is your universal adaptive subscription address.
    - For example `https://trauma.pages.dev/auto?sub` Base64 subscription format, suitable for PassWall, SSR+, etc.
    - For example `https://trauma.pages.dev/auto?clash` Clash subscription format, suitable for OpenClash, etc.
    - For example `https://trauma.pages.dev/auto?sb` singbox subscription format, suitable for singbox, etc.

4. Bind CNAME custom domain to Pages:
    - In the Pages console `Custom domains` tab, click below `Set up a custom domain`.
    - Fill in your custom secondary domain name, be careful not to use your root domain name, for example:
    - The domain name you are assigned is `fuck.cloudns.biz`, then add a custom field to fill in `iran.fuck.cloudns.biz` That’s it;
    - According to Cloudflare's requirements, your domain name DNS service provider will be returned and the custom domain will be added. `trauma` CNAME record of `trauma.pages.dev` After that, click `Activate Domain` That’s it.

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

## ProxyIP

1. When deploy in cloudflare pages, you can set proxyIP in 4th line of `_worker.js` file. or set environment variable, variable name is `PROXYIP`

2. When deploy in worker.dev, you can set proxyIP in 4th line of `_worker.js` file. or set environment variable, variable name is `proxyIP`

### How to find proxyIP 

[Let see here](https://github.com/NiREvil/vless/edit/main/sub/ProxyIP.md)



## Environment variables description

> [!NOTE]
> Only set two of them is sufficient, the first variable `PASSWORD` and the second `PROXYIP` , variables listed in the table below are only for educational purposes and additional explanations. 
![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)


| variable name | Example                                                                                                            | Remark                                                                                                                        |
| ------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------|
| PASSWORD      | auto                                                                                                               | Can take any value                                                                                                            |
| PROXYIP       |  `bpb.radically.pro` or anything else you want [see here](https://github.com/NiREvil/vless/edit/main/sub/ProxyIP.md)                 | Alternative proxy node for accessing CFCDN sites (supports multiple ProxyIPs, with ,1 or 2 line breaks between ProxyIPs))     |
| ADD           | `zula.ir,www.wto.org:2053`                                                   | Local preferred domain name/preferred IP (supports multiple elements`,`or line feed as interval)                              |
| ADDAPI        | https://raw.githubusercontent.com/NiREvil/Trauma/main/cleanIPs.txt                                                 | No need to explain, everyone understands                                                                                      |
|SUBAPI         | SUBAPI.fxxk.dedyn.io                                                                                               | clash, singbox, etc. subscription conversion backend                                                                          |
| SUBNAME       | REvil                                                                                                              | Subscription name                                                                                                             |
| ![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)  |    ![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)   |                                             ![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)   |

---


## Video tutorials 

https://github.com/NiREvil/Trauma/assets/126243832/92a430c3-4884-4831-bf8c-e328cfd78af8

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

  
https://github.com/NiREvil/Trauma/assets/126243832/f20a0215-bd75-4302-89dd-90a5bdd75cbc

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)  



https://github.com/NiREvil/Trauma/assets/126243832/f63c74c9-0e86-40a2-8894-e027c06776f5

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)  


  
https://github.com/NiREvil/Trauma/assets/126243832/61ce0b14-2c26-4325-a6c0-6f12cfc608d7

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)  


# grateful

[ca110us](https://github.com/ca110us/epeius)  |  [Sterilize it](https://github.com/3Kmfi6HP/EDtunnel/tree/trojan)  |  [zizifn](https://github.com/zizifn/edgetunnel)  | 
 [Yemen 178](https://github.com/emn178/js-sha256)  |  [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash/config)  |  [Shegs1999](https://github.com/SHIJS1999/cloudflare-worker-vless-ip)

 ![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)
