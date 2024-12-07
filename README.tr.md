# Sunucusuz CF Çalışanları ve Sayfaları kullanarak Truva Atı'nı dağıtın

🇮🇷[Farsça](README.fa.md)  
🇹🇷[Türkçe](README.tr.md)  
🇬🇧[İngilizce](README.md)  
🇩🇪[Almanya](README.de.md)

Bu, Cloudflare Worker platformunu temel alan bir komut dosyasıdır. Orijinal versiyona dayanarak, Truva atı yapılandırma bilgilerini görüntüleyecek ve bunu abonelik içeriğine dönüştürecek şekilde değiştirildi. Bu betiği kullanarak Truva atı yapılandırma bilgilerini çevrimiçi yapılandırmayı kullanarak Clash veya Singbox gibi araçlara kolayca dönüştürebilirsiniz.

[TG Kanalı](https://t.me/F_NiREvil)

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

## İçindekiler

-   [İşçi dağıtım yöntemi](#Workers-deployment-method)
-   [Sayfa dağıtım yöntemi](#Pages-deployment-method)
-   [proxyIP](#proxyIP)
-   [Ortam Değişkeni açıklaması](#Environment-variables-description)
-   [Video eğitimleri](#Video-tutorials)![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

<details>
<summary> Use </summary>

-   Bu proje yalnızca öğrenme, araştırma ve güvenlik testi amacıyla tasarlanmış ve geliştirilmiştir. Güvenlik araştırmacılarına, akademisyenlere ve teknoloji meraklılarına ağ iletişim teknolojisini anlamak ve uygulamak için bir araç sağlamayı amaçlamaktadır.
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

## İşçi dağıtım yöntemi

1.  Cloudflare Worker'ı dağıtın:

    -   Cloudflare Worker konsolunda yeni bir Worker oluşturun.

    -   İrade[işçi.js](_worker.js)İçeriği Worker düzenleyicisine yapıştırın.

    -   3\. satırı değiştir`password`Kendinize göre değiştirin**şifre**

    -   Alternatif olarak, doğrudan dağıtmak için aşağıdaki düğmeye tıklayabilirsiniz.

    [![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/NiREvil/Trauma)

2.  Tercih edilen rotayı ekle:
    -   Vermek`addresses`Tercih edilen alan adını/tercih edilen temiz IP'yi formata göre ekleyin. Bağlantı noktası numarası yoksa varsayılan TLS bağlantı noktası 443'tür ve # işareti açıklama takma adıdır, örneğin:
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

3.  Abonelik içeriğine erişin:
    -   erişim`https://[YOUR-WORKERS-URL]/[password]`Abonelik içeriğini alın.
    -   Örneğin`https://vless.trauma.workers.dev/auto`Bu sizin evrensel uyarlanabilir abonelik adresinizdir.
    -   Örneğin`https://vless.trauma.workers.dev/auto?sub`Base64 abonelik formatı; PassWall, SSR+ vb. için uygundur.
    -   Örneğin`https://vless.trauma.workers.dev/auto?clash`OpenClash vb. için uygun Clash abonelik formatı.
    -   Örneğin`https://vless.trauma.workers.dev/auto?sb`singbox abonelik formatı, singbox vb. için uygundur.

4.  Çalışanlara özel bir alan adı bağlayın:
    -   İşçi konsolunda`trigger`sekme, aşağıya tıklayın`Add a custom domain`。
    -   CloudFlare alan adı çözümleme hizmetine aktardığınız ikincil alan adını girin, örneğin:`vless.trauma.com`Tıkladıktan sonra`Add a custom domain`, sertifikanın geçerli olmasını bekleyin.

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

## Sayfa dağıtım yöntemi

1.  Cloudflare Sayfalarını Dağıtın:
    -   Çatal[Github'daki bu proje](https://github.com/NiREvil/Trauma/fork)
    -   Cloudflare Sayfaları konsolunda seçin`Connected to Git`Bundan sonra seçin`trauma`Öğeden sonra tıklayın`Start setting up`。
    -   var olmak`Setting up build and deployment`Sayfanın alt kısmında`Environment variables (advanced)`daha sonra birleştir[Değişken ekle](#Environment-variables-description),
    -   Değişken adını girin**ŞİFRE**, değer şifrenizdir, ardından tıklayın`Save and deploy`İşte bu.

2.  Tercih edilen rotayı ekle:
    -   Değişken ekle`ADD`Yerel statik tercihli hat; bağlantı noktası numarası yoksa, varsayılan TLS bağlantı noktası 443'tür ve # numarasının ardından bir açıklama takma adı gelir, örneğin:
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

3.  Abonelik içeriğine erişin:
    -   erişim`https://[YOUR-PAGES-URL]/[password]`Abonelik içeriği mevcuttur.
    -   Örneğin`https://trauma.pages.dev/auto`Bu sizin evrensel uyarlanabilir abonelik adresinizdir.
    -   Örneğin`https://trauma.pages.dev/auto?sub`Base64 abonelik formatı; PassWall, SSR+ vb. için uygundur.
    -   Örneğin`https://trauma.pages.dev/auto?clash`OpenClash vb. için uygun Clash abonelik formatı.
    -   Örneğin`https://trauma.pages.dev/auto?sb`singbox abonelik formatı, singbox vb. için uygundur.

4.  CNAME özel alan adını Sayfalara bağlayın:
    -   Sayfalar konsolunda`Custom domains`sekme, aşağıya tıklayın`Set up a custom domain`.
    -   Özel ikincil alan adınızı girin, kök alan adınızı kullanmamaya dikkat edin, örneğin:
    -   Size atanan alan adı`fuck.cloudns.biz`, ardından doldurulacak özel bir alan ekleyin`iran.fuck.cloudns.biz`İşte bu;
    -   Cloudflare gereksinimlerine göre alan adı DNS servis sağlayıcınız iade edilecek ve özel alan adı eklenecektir.`trauma`CNAME kaydı`trauma.pages.dev`Bundan sonra tıklayın`Activate Domain`İşte bu.

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

## ProxyIP

1.  Cloudflare sayfalarında dağıtım yaparken proxyIP'yi 4. satırda ayarlayabilirsiniz.`_worker.js`dosya. veya ortam değişkenini ayarlayın, değişken adı`PROXYIP`

2.  Worker.dev'de dağıtım yaparken proxyIP'yi 4. satırda ayarlayabilirsiniz.`_worker.js`dosya. veya ortam değişkenini ayarlayın, değişken adı`proxyIP`

### ProxyIP nasıl bulunur?

[Burada görelim](https://github.com/NiREvil/vless/edit/main/sub/ProxyIP.md)

## Ortam değişkenleri açıklaması

> [!NOT]Bunlardan sadece ikisini ayarlamak yeterli, ilk değişken`PASSWORD`ve ikincisi`PROXYIP`, aşağıdaki tabloda listelenen değişkenler yalnızca eğitim amaçlıdır ve ek açıklamalar içindir.![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

| değişken adı                                                                                       | Örnek                                                                                                                  | Açıklama                                                                                                                                      |
| -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| ŞİFRE                                                                                              | oto                                                                                                                    | Her değeri alabilir                                                                                                                           |
| PROXYIP                                                                                            | `bpb.radically.pro`veya istediğin başka bir şey[buraya bak](https://github.com/NiREvil/vless/edit/main/sub/ProxyIP.md) | CFCDN sitelerine erişim için alternatif proxy düğümü (ProxyIP'ler arasında 1 veya 2 satır aralığı bulunan birden fazla ProxyIP'yi destekler)) |
| EKLEMEK                                                                                            | `zula.ir,www.wto.org:2053`                                                                                             | Yerel tercih edilen alan adı/tercih edilen IP (birden fazla öğeyi destekler)`,`veya aralık olarak satır besleme)                              |
| EKLEMEK                                                                                            | <https://raw.githubusercontent.com/NiREvil/Trauma/main/cleanIPs.txt>                                                   | Açıklamaya gerek yok herkes anlıyor                                                                                                           |
| subapi                                                                                             | SUBAPI.fxxk.dedyn.io                                                                                                   | Clash, singbox vb. abonelik dönüşümü arka ucu                                                                                                 |
| ALT AD                                                                                             | kötü                                                                                                                   | Abonelik adı                                                                                                                                  |
| ![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256) | ![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)                     | ![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)                                            |

* * *

## Video eğitimleri

<https://github.com/NiREvil/Trauma/assets/126243832/92a430c3-4884-4831-bf8c-e328cfd78af8>

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

<https://github.com/NiREvil/Trauma/assets/126243832/f20a0215-bd75-4302-89dd-90a5bdd75cbc>

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

<https://github.com/NiREvil/Trauma/assets/126243832/f63c74c9-0e86-40a2-8894-e027c06776f5>

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

<https://github.com/NiREvil/Trauma/assets/126243832/61ce0b14-2c26-4325-a6c0-6f12cfc608d7>

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)

# minnettar

[ca110us](https://github.com/ca110us/epeius)\|[Sterilize et](https://github.com/3Kmfi6HP/EDtunnel/tree/trojan)\|[zizifn](https://github.com/zizifn/edgetunnel)\|[Yemen 178](https://github.com/emn178/js-sha256)\|[ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash/config)\|[Shegs 1999](https://github.com/SHIJS1999/cloudflare-worker-vless-ip)

![rainbow](https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256)
