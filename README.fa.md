# پیکربندی تروجان را با استفاده از CF-Workers & Pages بدون سرور اجرا کنید.

🇮🇷 [فارسی](README.fa.md)    🇹🇷 [ترکی](README.tr.md)  

🇬🇧 [انگلیسی](README.md)    🇩🇪 [آلمانی](README.de.md)  



این یک اسکریپت مبتنی بر پلتفرم Cloudflare Worker است. بر اساس نسخه اصلی، برای نمایش اطلاعات پیکربندی تروجان و تبدیل آن به محتوای اشتراک اصلاح شده است. با استفاده از این اسکریپت می توانید به راحتی اطلاعات پیکربندی تروجان را با استفاده از پیکربندی آنلاین به ابزارهایی مانند Clash یا Singbox تبدیل کنید.

[کانال تلگرام](https://t.me/F_NiREvil)

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

## فهرست مطالب

  - [روش پیکربندی وورکر](#روش-پیکربندی-وورکر)
  - [روش پیکربندی‌ پیج](#روش-پیکربندی-پیج)
  - [پروکسی آیپی](#پروکسی-آیپی)
  - [شرح متغیرها](#Environment-variables-description)
  - [ کلیپ های آموزش ](#کلیپ-های-آموزش)

  ![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)
  

<details>
<summary> use </summary>

-   این پروژه فقط برای اهداف یادگیری، تحقیق و تست ایمنی طراحی و توسعه یافته است. هدف آن ارائه ابزاری به محققان امنیتی، دانشگاهیان و علاقه مندان به فناوری برای درک و تمرین فناوری ارتباطات شبکه است.
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





## روش پیکربندی وورکر

1. پبکربندی Cloudflare Worker
    -   یک Worker جدید در کنسول Cloudflare Worker ایجاد کنید.
    -   ابتدا فایل [worker.js](_worker.js) کپی کرده و در ویرایشگر Worker قرار دهید.
    -  خط سوم آن را که شامل `password` می‌باشد به **کلمه عبور** دلخواه خود تغییر دهید.
    
    -  همچنین میتوانید از طریق دکمه زیر ساخت را شروع کنید:
    
    -  [![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/NiREvil/Trauma)
  
      ![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)
    

2. اضافه کردن دامنه یا آی‌پی تمیز
    - اضافه کردن `addresses` نام دامنه یا آی‌پی تمیز ترجیحی را با توجه به فرمت اضافه کنید. اگر شماره پورتی وجود نداشته باشد، پورت پیش‌فرض TLS 443 است و بعد از علامت # نام مستعار Remark را بنویسید، برای مثال:
        ```js
        let addresses = [
        // any Domain or clean IPv4/IPv6 addresses from cloudflare is usable, no sweat.
        'cdnjs.com:443#N1',
        'www.wto.org:2053#N2',
        'sky.rethinkdns.com#N3',
        'creativecommons.org#N4',
        '[2606:4700:310c::ac42:2c39]#N5 √IPv6',
      ];

3. دسترسی به محتوای لینک ساب
    -  با قرار دادن یک `/` و `UUID` خود در انتهای لینک وورکر مانند: `https://[YOUR-WORKERS-URL]/[password]` به محتوای اشتراک خود دسترسی پیدا کنید.
    - مثلا `https://vless.trauma.workers.dev/auto` این آدرس اشتراک تطبیقی کلی شماست.
    - مثلا `https://vless.trauma.workers.dev/auto?sub` فرمت اشتراک Base64، مناسب برای PassWall، SSR+ و غیره.
    - مثلا ` https://vless.trauma.workers.dev/auto?clash` فرمت اشتراک کلش، مناسب برای OpenClash و غیره.
      - مثلا ` https://vless.trauma.workers.dev/auto?sb` فرمت اشتراک singbox، مناسب برای singbox و غیره.

4. یک دامنه سفارشی را به وورکر متصل کنید
    -  در کنسول وورکر `trigger` برگه، در زیر کلیک کنید `Add a custom domain`。
    -  نام دامنه ثانویه ای را که به سرویس حل نام دامنه CloudFlare منتقل کرده اید را وارد کنید، به عنوان مثال: `vless.trauma.com` پس از کلیک `Add a custom domain` ، فقط منتظر بمانید تا گواهی اجرا شود.

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

## روش پیکربندی پیج

1. پیکربندی  Pages Cloudflare:
    - در ابتدا لازم است که این مخزن را فورک بزنید [لینک مخزن در Github](https://github.com/NiREvil/Trauma/fork)
    - در اکانت کلادفلر خود **workers & Pages** را انتخاب کنید و سپس گزینه `create application` و پی از ان `create pages` و `Connected to Git` را انتخاب کنید `trauma` سپس روی `Start setting up` کلیک کنید。
    - وجود داشته باشد `Setting up build and deployment` در پایین صفحه، را انتخاب کنید `Environment variables (advanced)` بعدا ادغام شوند [متغیرها را اضافه کنید](#Variable-description),
    - نام متغیر را پر کنید **کلمه عبور**، مقدار رمز عبور شما است، سپس کلیک کنید`Save and deploy`خودشه.

2. :اضافه کردن مسیر ترجیحی

- متغیرها را اضافه کنید `ADD` خط ترجیحی استاتیک محلی، اگر شماره پورتی وجود نداشته باشد، پورت پیش‌فرض TLS 443 است و بعد از علامت #  نام مستعار Remark را بنویسید، برای مثال:
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

3.  دسترسی به محتوای لینک ساب:
    - با قرار دادن یک `/` و `UUID` خود در انتهای لینک وورکر مانند: `https://[YOUR-WORKERS-URL]/[password]` به محتوای اشتراک خود دسترسی پیدا کنید
    - مثلا `https://trauma.pages.dev/auto` این آدرس اشتراک تطبیقی کلی شماست.
    - مثلا `https://trauma.pages.dev/auto?sub` فرمت اشتراک Base64، مناسب برای PassWall، SSR+ و غیره.
    -   مثلا `https://trauma.pages.dev/auto?clash` فرمت اشتراک کلش، مناسب برای OpenClash و غیره.
    -   مثلا `https://trauma.pages.dev/auto?sb` فرمت اشتراک singbox، مناسب برای singbox و غیره.

4.  دامنه سفارشی CNAME را به صفحات متصل کنید:
    - در کنسول Pages `Custom domains` برگه، در زیر کلیک کنید `Set up a custom domain`.
    - نام ساب دامنه خود را وارد کنید، مراقب باشید از نام دامنه ریشه خود استفاده نکنید، به عنوان مثال:
    - نام دامنه ای که به شما اختصاص داده شده است `fuck.cloudns.biz` ، سپس یک فیلد سفارشی برای پر کردن اضافه کنید `iran.fuck.cloudns.biz`؛
    - با توجه به الزامات Cloudflare، نام دامنه شما ارائه دهنده خدمات DNS بازگردانده خواهد شد و دامنه سفارشی اضافه خواهد شد. `trauma` رکورد CNAME از `trauma.pages.dev` پس از آن، کلیک کنید `Activate Domain` خودشه.

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

## پروکسی آیپی

1.  هنگام پیکربندی‌ در Pages cloudflare، می توانید پروکسی IP را در فایل `worker.js` تنظیم کنید. و یا یک متغیر با نام `PROXYIP` ایجاد کنید.

2.  هنگام پیکربندی در worker.dev، نیز می توانید پروکسی IP را در کد فایل آن تنظیم کنید `_worker.js` فایل. یا یک متغیر با نام `proxyIP` ایحاد کنید.


![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

**نحوه پیدا کردن پروکسی IP**

[به اینجا سر بزنید](https://github.com/NiREvil/vless/edit/main/sub/ProxyIP.md)  

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)





## شرح متغیرها

> [!NOTE]
> تنها مجموعه دو مورد از آنها کافی است، متغیر اول `PASSWORD` و دومی `PROXYIP` ، متغیرهای ذکر شده در جدول زیر فقط برای اهداف آموزشی و توضیحات تکمیلی هستند.

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

| نام متغیر         | مثال                                                                                                                                           | تذکر دهید                                                                                                                                                                                   |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PASSWORD         | خودکار                                                                                                                                         | می تواند هر ارزشی را بگیرد                                                                                                                                                                  |
| PROXYIP      |  `bpb.radically.pro` or Use anything else you want [به اینجا سر بزنید](https://github.com/NiREvil/vless/edit/main/sub/ProxyIP.md)                                     | به عنوان یک گره پروکسی برای دسترسی به سایت CloudFlareCDN (پشتیبانی از ProxyIP های متعدد، مورد استفاده بین ProxyIP ها `,` یا تغذیه خط به عنوان فاصله)                                          |
| ADD        | `zula.ir,www.wto.org:2053`                                                                                   | نام دامنه ترجیحی محلی / IP ترجیحی (از چندین عنصر پشتیبانی می کند `,` یا تغذیه خط به عنوان فاصله)                                                                                              |
| ADDAPI            | <https://raw.githubusercontent.com/NiREvil/Trauma/main/cleanIPs.txt>                                                                           | نیازی به توضیح نیست، همه می فهمند                                                                                                                                                           |
| ADDCSV            |                                                                                                                                                | نیازی به توضیح نیست، همه می فهمند                                                                                                                                                           |
| DLS               | 8                                                                                                                                              | نیازی به توضیح نیست، همه می فهمند                                                                                                                                                           |
| TGTOKEN           | 6894123456:XXXXXXXXX0qExVsBPUhHDAbXXXXXXqWXgBA                                                                                                 | توکن ربات برای ارسال اعلان های TG                                                                                                                                                           |
| TGID | 6946912345                                                                                                                                     |  دیجیتالی حساب برای دریافت اعلان های TG                                                                                                                                                |
| SUB               | trojan.fxxk.dedyn.io                                                                                                                           |  مولد اشتراک ترجیحی (استفاده از مشترک منصرف خواهد شد `ADD` محتوای اشتراک ممتاز محلی در )                                                                                                  |
| SUBAPI            | `SUBAPI.fxxk.dedyn.io`                                                                                                                                   | clash، singbox، و غیره تبدیل اشتراک                                                                                                                                                    |
| SUBCONFIG         | [https://raw.github.../ACL4SSR_Online_Mini.ini](https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini) | clash، singbox، و غیره. پروفایل های تبدیل اشتراک                                                                                                                                            |
| SUBNAME           | REvil                                                                                                                                          | نام اشتراک                                                                                                                                                                                  |
| 02                | <https://t.me/F_NiREvil>                                                                                                                       | پرش صفحه اصلی 302 (از چندین URL پشتیبانی می کند، بین URL ها استفاده می شود) `,`یا شکستن خط به عنوان فاصله‌دهنده، اگر تازه کار هستید از آن استفاده نکنید)                                     |
| URL               | <https://t.me/F_NiREvil>                                                                                                                       | پنهان کردن صفحه اصلی (از چندین URL پشتیبانی می کند، بین URL ها استفاده می شود) `,`یا از شکست های خط به عنوان فواصل استفاده کنید، تنظیمات تصادفی به راحتی می تواند ضد تقلب را راه اندازی کند) |

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)  


  

## کلیپ های آموزش 

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
