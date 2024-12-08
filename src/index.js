import { connect } from "cloudflare:sockets";

let password = '';
let proxyIP = '';
let sub = ''; 
let subConverter = 'SUBAPI.fxxk.dedyn.io';// clash订阅转换后端，目前使用CM的订阅转换功能。自带虚假节点信息防泄露
let subConfig = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini"; //订阅配置文件
let subProtocol = 'https';
let subEmoji = 'true';
let socks5Address = '';
let parsedSocks5Address = {}; 
let enableSocks = false;

let fakeUserID ;
let fakeHostName ;
const expire = 4102329600;//2099-12-31
let proxyIPs ;
let socks5s;
let go2Socks5s = [
	'*ttvnw.net',
	'*tapecontent.net',
	'*cloudatacdn.com',
	'*.loadshare.org',
];
let addresses = [];
let addressesapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1;//CSV备注所在列偏移量
let FileName = 'epeius';
let BotToken ='';
let ChatID =''; 
let proxyhosts = [];
let proxyhostsURL = '';
let RproxyIP = 'false';
let httpsPorts = ["2053","2083","2087","2096","8443"];
let sha224Password ;
const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
let proxyIPPool = [];
let path = '/?ed=2560';
export default {
	async fetch(request, env, ctx) {
		try {
			const UA = request.headers.get('User-Agent') || 'null';
			const userAgent = UA.toLowerCase();
			password = env.PASSWORD || env.pswd || env.UUID || env.uuid || password;
			if (!password) {
				return new Response('请设置你的PASSWORD变量，或尝试重试部署，检查变量是否生效？', { 
					status: 404,
					headers: {
						"Content-Type": "text/plain;charset=utf-8",
					}
				});
			}
			sha224Password = env.SHA224 || env.SHA224PASS || sha224(password);
			//console.log(sha224Password);

			const currentDate = new Date();
			currentDate.setHours(0, 0, 0, 0); // 设置时间为当天
			const timestamp = Math.ceil(currentDate.getTime() / 1000);
			const fakeUserIDMD5 = await MD5MD5(`${password}${timestamp}`);
			fakeUserID = [
				fakeUserIDMD5.slice(0, 8),
				fakeUserIDMD5.slice(8, 12),
				fakeUserIDMD5.slice(12, 16),
				fakeUserIDMD5.slice(16, 20),
				fakeUserIDMD5.slice(20)
			].join('-');
			
			fakeHostName = `${fakeUserIDMD5.slice(6, 9)}.${fakeUserIDMD5.slice(13, 19)}`;
			
			proxyIP = env.PROXYIP || env.proxyip || proxyIP;
			proxyIPs = await ADD(proxyIP);
			proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];

			socks5Address = env.SOCKS5 || socks5Address;
			socks5s = await ADD(socks5Address);
			socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
			socks5Address = socks5Address.split('//')[1] || socks5Address;
			if (env.GO2SOCKS5) go2Socks5s = await ADD(env.GO2SOCKS5);
			if (env.CFPORTS) httpsPorts = await ADD(env.CFPORTS);

			if (socks5Address) {
				try {
					parsedSocks5Address = socks5AddressParser(socks5Address);
					RproxyIP = env.RPROXYIP || 'false';
					enableSocks = true;
				} catch (err) {
  					/** @type {Error} */ 
					let e = err;
					console.log(e.toString());
					RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
					enableSocks = false;
				}
			} else {
				RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
			}

			const upgradeHeader = request.headers.get("Upgrade");
			const url = new URL(request.url);
			if (!upgradeHeader || upgradeHeader !== "websocket") {
				if (env.ADD) addresses = await ADD(env.ADD);
				if (env.ADDAPI) addressesapi = await ADD(env.ADDAPI);
				if (env.ADDCSV) addressescsv = await ADD(env.ADDCSV);
				DLS = Number(env.DLS) || DLS;
				remarkIndex = Number(env.CSVREMARK) || remarkIndex;
				BotToken = env.TGTOKEN || BotToken;
				ChatID = env.TGID || ChatID; 
				FileName = env.SUBNAME || FileName;
				subEmoji = env.SUBEMOJI || env.EMOJI || subEmoji;
				if(subEmoji == '0') subEmoji = 'false';

				sub = env.SUB || sub;
				subConverter = env.SUBAPI || subConverter;
				if (subConverter.includes("http://") ){
					subConverter = subConverter.split("//")[1];
					subProtocol = 'http';
				} else {
					subConverter = subConverter.split("//")[1] || subConverter;
				}
				subConfig = env.SUBCONFIG || subConfig;
				if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub');

				if (url.searchParams.has('proxyip')) {
					path = `/?ed=2560&proxyip=${url.searchParams.get('proxyip')}`;
					RproxyIP = 'false';
				} else if (url.searchParams.has('socks5')) {
					path = `/?ed=2560&socks5=${url.searchParams.get('socks5')}`;
					RproxyIP = 'false';
				} else if (url.searchParams.has('socks')) {
					path = `/?ed=2560&socks5=${url.searchParams.get('socks')}`;
					RproxyIP = 'false';
				}
				switch (url.pathname) {
				case '/':
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await proxyURL(env.URL, url);
					else return new Response(JSON.stringify(request.cf, null, 4), {
						status: 200,
						headers: {
							'content-type': 'application/json',
						},
					});
				case `/${fakeUserID}`:
					const fakeConfig = await get特洛伊Config(password, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url);
					return new Response(`${fakeConfig}`, { status: 200 });
				case `/${password}`:
					await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
					const 特洛伊Config = await get特洛伊Config(password, request.headers.get('Host'), sub, UA, RproxyIP, url);
					const now = Date.now();
					//const timestamp = Math.floor(now / 1000);
					const today = new Date(now);
					today.setHours(0, 0, 0, 0);
					const UD = Math.floor(((now - today.getTime())/86400000) * 24 * 1099511627776 / 2);
					let pagesSum = UD;
					let workersSum = UD;
					let total = 24 * 1099511627776 ;

					if (userAgent && (userAgent.includes('mozilla') || userAgent.includes('subconverter'))){
						return new Response(`${特洛伊Config}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					} else {
						return new Response(`${特洛伊Config}`, {
							status: 200,
							headers: {
								"Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					}
				default:
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await proxyURL(env.URL, url);
					else return new Response('不用怀疑！你PASSWORD就是错的！！！', { status: 404 });
				}
			} else {
				socks5Address = url.searchParams.get('socks5') || socks5Address;
				if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
				else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname)) {
					socks5Address = url.pathname.split('://')[1].split('#')[0];
					if (socks5Address.includes('@')){
						let userPassword = socks5Address.split('@')[0];
						const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
						if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
						socks5Address = `${userPassword}@${socks5Address.split('@')[1]}`;
					}
				}

				if (socks5Address) {
					try {
						parsedSocks5Address = socks5AddressParser(socks5Address);
						enableSocks = true;
					} catch (err) {
						/** @type {Error} */ 
						let e = err;
						console.log(e.toString());
						enableSocks = false;
					}
				} else {
					enableSocks = false;
				}

				if (url.searchParams.has('proxyip')){
					proxyIP = url.searchParams.get('proxyip');
					enableSocks = false;
				} else if (new RegExp('/proxyip=', 'i').test(url.pathname)) {
					proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
					enableSocks = false;
				} else if (new RegExp('/proxyip.', 'i').test(url.pathname)) {
					proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
					enableSocks = false;
				}

				return await 特洛伊OverWSHandler(request);
			}
		} catch (err) {
			let e = err;
			return new Response(e.toString());
		}
	}
};

async function 特洛伊OverWSHandler(request) {
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);
	webSocket.accept();
	let address = "";
	let portWithRandomLog = "";
	const log = (info, event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
	};
	const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
	let remoteSocketWapper = {
		value: null
	};
	let udpStreamWrite = null;
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter();
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}
			const {
				hasError,
				message,
				portRemote = 443,
				addressRemote = "",
				rawClientData,
				addressType
			} = await parse特洛伊Header(chunk);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
			if (hasError) {
				throw new Error(message);
				return;
			}
			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log, addressType);
		},
		close() {
			log(`readableWebSocketStream is closed`);
		},
		abort(reason) {
			log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
		}
	})).catch((err) => {
		log("readableWebSocketStream pipeTo error", err);
	});
	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: client
	});
}

async function parse特洛伊Header(buffer) {
	if (buffer.byteLength < 56) {
		return {
			hasError: true,
			message: "invalid data"
		};
	}
	let crLfIndex = 56;
	if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
		return {
			hasError: true,
			message: "invalid header format (missing CR LF)"
		};
	}
	const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
	if (password !== sha224Password) {
		return {
			hasError: true,
			message: "invalid password"
		};
	}

	const socks5DataBuffer = buffer.slice(crLfIndex + 2);
	if (socks5DataBuffer.byteLength < 6) {
		return {
			hasError: true,
			message: "invalid SOCKS5 request data"
		};
	}

	const view = new DataView(socks5DataBuffer);
	const cmd = view.getUint8(0);
	if (cmd !== 1) {
		return {
			hasError: true,
			message: "unsupported command, only TCP (CONNECT) is allowed"
		};
	}

	const atype = view.getUint8(1);
	// 0x01: IPv4 address
	// 0x03: Domain name
	// 0x04: IPv6 address
	let addressLength = 0;
	let addressIndex = 2;
	let address = "";
	switch (atype) {
	case 1:
		addressLength = 4;
		address = new Uint8Array(
			socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
		).join(".");
		break;
	case 3:
		addressLength = new Uint8Array(
			socks5DataBuffer.slice(addressIndex, addressIndex + 1)
		)[0];
		addressIndex += 1;
		address = new TextDecoder().decode(
			socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
		);
		break;
	case 4:
		addressLength = 16;
		const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
		const ipv6 = [];
		for (let i = 0; i < 8; i++) {
			ipv6.push(dataView.getUint16(i * 2).toString(16));
		}
		address = ipv6.join(":");
		break;
	default:
		return {
			hasError: true,
			message: `invalid addressType is ${atype}`
		};
	}

	if (!address) {
		return {
			hasError: true,
			message: `address is empty, addressType is ${atype}`
		};
	}

	const portIndex = addressIndex + addressLength;
	const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);
	return {
		hasError: false,
		addressRemote: address,
		portRemote,
		rawClientData: socks5DataBuffer.slice(portIndex + 4),
		addressType: atype
	};
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log, addressType) {
	async function useSocks5Pattern(address) {
		if ( go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg==')) ) return true;
		return go2Socks5s.some(pattern => {
			let regexPattern = pattern.replace(/\*/g, '.*');
			let regex = new RegExp(`^${regexPattern}$`, 'i');
			return regex.test(address);
		});
	}
	async function connectAndWrite(address, port, socks = false) {
		log(`connected to ${address}:${port}`);
		//if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LmlwLjA5MDIyNy54eXo=')}`;
		const tcpSocket = socks ? await socks5Connect(addressType, address, port, log)
		: connect({
			hostname: address,
			port
		});
		remoteSocket.value = tcpSocket;
		//log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}
	async function retry() {
		if (enableSocks) {
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
		} else {
			if (!proxyIP || proxyIP == '') {
				proxyIP = atob('UFJPWFlJUC50cDEuZnh4ay5kZWR5bi5pbw==');
			} else if (proxyIP.includes(']:')) {
				portRemote = proxyIP.split(']:')[1] || portRemote;
				proxyIP = proxyIP.split(']:')[0] || proxyIP;
			} else if (proxyIP.split(':').length === 2) {
				portRemote = proxyIP.split(':')[1] || portRemote;
				proxyIP = proxyIP.split(':')[0] || proxyIP;
			}
			if (proxyIP.includes('.tp')) portRemote = proxyIP.split('.tp')[1].split('.')[0] || portRemote;
			tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
		}
		tcpSocket.closed.catch((error) => {
			console.log("retry tcpSocket closed error", error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		});
		remoteSocketToWS(tcpSocket, webSocket, null, log);
	}
	let useSocks = false;
	if (go2Socks5s.length > 0 && enableSocks ) useSocks = await useSocks5Pattern(addressRemote);
	let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks);
	remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener("message", (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});
			webSocketServer.addEventListener("close", () => {
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			});
			webSocketServer.addEventListener("error", (err) => {
				log("webSocketServer error");
				controller.error(err);
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},
		pull(controller) {},
		cancel(reason) {
			if (readableStreamCancel) {
				return;
			}
			log(`readableStream was canceled, due to ${reason}`);
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});
	return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
	let hasIncomingData = false;
	await remoteSocket.readable.pipeTo(
		new WritableStream({
			start() {},
			/**
			 *
			 * @param {Uint8Array} chunk
			 * @param {*} controller
			 */
			async write(chunk, controller) {
				hasIncomingData = true;
				if (webSocket.readyState !== WS_READY_STATE_OPEN) {
					controller.error(
						"webSocket connection is not open"
					);
				}
				webSocket.send(chunk);
			},
			close() {
				log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
			},
			abort(reason) {
				console.error("remoteSocket.readable abort", reason);
			}
		})
	).catch((error) => {
		console.error(
			`remoteSocketToWS error:`,
			error.stack || error
		);
		safeCloseWebSocket(webSocket);
	});
	if (hasIncomingData === false && retry) {
		log(`retry`);
		retry();
	}
}
/*
function isValidSHA224(hash) {
	const sha224Regex = /^[0-9a-f]{56}$/i;
	return sha224Regex.test(hash);
}
*/
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { error };
	}
}

let WS_READY_STATE_OPEN = 1;
let WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error("safeCloseWebSocket error", error);
	}
}

/*
export {
	worker_default as
	default
};
//# sourceMappingURL=worker.js.map
*/

function revertFakeInfo(content, userID, hostName, isBase64) {
    if (isBase64) content = atob(content); // Base64 decode
    content = content.replace(new RegExp(fakeUserID, 'g'), userID).replace(new RegExp(fakeHostName, 'g'), hostName);
    //console.log(content);
    if (isBase64) content = btoa(content); // Base64 encode

    return content;
}

async function MD5MD5(text) {
    const encoder = new TextEncoder();

    const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
    const firstPassArray = Array.from(new Uint8Array(firstPass));
    const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

    const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
    const secondPassArray = Array.from(new Uint8Array(secondPass));
    const secondHex = secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return secondHex.toLowerCase();
}

async function ADD(content) {
    // Replace tabs, double quotes, single quotes, and newline characters with commas
    // Then replace consecutive commas with a single comma
    var replacedContent = content.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');

    // Remove leading and trailing commas (if any)
    if (replacedContent.charAt(0) == ',') replacedContent = replacedContent.slice(1);
    if (replacedContent.charAt(replacedContent.length - 1) == ',') replacedContent = replacedContent.slice(0, replacedContent.length - 1);

    // Split the string by commas to get the address array
    const addressArray = replacedContent.split(',');

    return addressArray;
}

async function proxyURL(proxyURL, url) {
    const URLs = await ADD(proxyURL);
    const fullURL = URLs[Math.floor(Math.random() * URLs.length)];
    // Parse the target URL
    let parsedURL = new URL(fullURL);
    console.log(parsedURL);
    // Extract and possibly modify URL components
    let URLProtocol = parsedURL.protocol.slice(0, -1) || 'https';
    let URLHostname = parsedURL.hostname;
    let URLPathname = parsedURL.pathname;
    let URLSearch = parsedURL.search;
    // Handle pathname
    if (URLPathname.charAt(URLPathname.length - 1) == '/') {
        URLPathname = URLPathname.slice(0, -1);
    }
    URLPathname += url.pathname;
    // Build the new URL
    let newURL = `${URLProtocol}://${URLHostname}${URLPathname}${URLSearch}`;
    // Reverse proxy request
    let response = await fetch(newURL);
    // Create a new response
    let newResponse = new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
    });
    // Add custom headers containing URL information
    //newResponse.headers.set('X-Proxied-By', 'Cloudflare Worker');
    //newResponse.headers.set('X-Original-URL', fullURL);
    newResponse.headers.set('X-New-URL', newURL);
    return newResponse;
}

function 配置信息(password, domainAddress) {
    const 啥啥啥_写的这是啥啊 = 'trojan';
    const protocolType = atob(啥啥啥_写的这是啥啊);

    const alias = FileName;
    let address = domainAddress;
    let port = 443;

    const transportProtocol = 'ws';
    const disguisedDomain = domainAddress;
    const path = path;

    let transportSecurity = ['tls', true];
    const SNI = domainAddress;
    const fingerprint = 'randomized';

    const v2ray = `${protocolType}://${encodeURIComponent(password)}@${address}:${port}?security=${transportSecurity[0]}&sni=${SNI}&alpn=h3&fp=${fingerprint}&allowInsecure=1&type=${transportProtocol}&host=${disguisedDomain}&path=${encodeURIComponent(path)}#${encodeURIComponent(alias)}`
    const clash = `- {name: ${alias}, server: ${address}, port: ${port}, udp: false, client-fingerprint: ${fingerprint}, type: ${protocolType}, password: ${password}, sni: ${SNI}, alpn: [h3], skip-cert-verify: true, network: ${transportProtocol}, ws-opts: {path: "${path}", headers: {Host: ${disguisedDomain}}}}`;

    return [v2ray, clash];
}

let subParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb', 'surge'];
async function get特洛伊Config(password, hostName, sub, UA, RproxyIP, _url) {
    if (sub) {
        const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
        if (match) {
            sub = match[1];
        }
        const subs = await ADD(sub);
        if (subs.length > 1) sub = subs[0];

    } else if ((addresses.length + addressesapi.length + addressescsv.length) == 0) {
        // Define the CIDR list of Cloudflare IP ranges
        let cfips = [
            '103.21.244.0/23',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '172.64.0.0/14',
            '103.21.244.0/23',
            '104.16.0.0/14',
            '104.24.0.0/15',
            '141.101.64.0/19',
            '172.64.0.0/14',
            '188.114.96.0/21',
            '190.93.240.0/21',
        ];

        // Generate a random IP address within the given CIDR range
        function generateRandomIPFromCIDR(cidr) {
            const [base, mask] = cidr.split('/');
            const baseIP = base.split('.').map(Number);
            const subnetMask = 32 - parseInt(mask, 10);
            const maxHosts = Math.pow(2, subnetMask) - 1;
            const randomHost = Math.floor(Math.random() * maxHosts);

            const randomIP = baseIP.map((octet, index) => {
                if (index < 2) return octet;
                if (index === 2) return (octet & (255 << (subnetMask - 8))) + ((randomHost >> 8) & 255);
                return (octet & (255 << subnetMask)) + (randomHost & 255);
            });

            return randomIP.join('.');
        }
        addresses = addresses.concat('127.0.0.1:1234#CFnat');
        addresses = addresses.concat(cfips.map(cidr => generateRandomIPFromCIDR(cidr) + '#CF随机节点'));
    }
    const userAgent = UA.toLowerCase();
    const Config = 配置信息(password, hostName);
    const v2ray = Config[0];
    const clash = Config[1];
    let proxyhost = "";
    if (hostName.includes(".workers.dev")) {
        if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
            try {
                const response = await fetch(proxyhostsURL);

                if (!response.ok) {
                    console.error('Error fetching addresses:', response.status, response.statusText);
                    return; // If there is an error, return directly
                }

                const text = await response.text();
                const lines = text.split('\n');
                // Filter out empty lines or lines containing only whitespace
                const nonEmptyLines = lines.filter(line => line.trim() !== '');

                proxyhosts = proxyhosts.concat(nonEmptyLines);
            } catch (error) {
                //console.error('Error fetching addresses:', error);
            }
        }
        if (proxyhosts.length != 0) proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
    }

    if (userAgent.includes('mozilla') && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
        let surge = `Surge subscription address:\nhttps://${proxyhost}${hostName}/${password}?surge`;
        if (hostName.includes(".workers.dev")) surge = "Surge subscription must bind a custom domain";
        const newSocks5s = socks5s.map(socks5Address => {
            if (socks5Address.includes('@')) return socks5Address.split('@')[1];
            else if (socks5Address.includes('//')) return socks5Address.split('//')[1];
            else return socks5Address;
        });

        let socks5List = '';
        if (go2Socks5s.length > 0 && enableSocks) {
            socks5List = `${decodeURIComponent('SOCKS5%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20')}`;
            if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) socks5List += `${decodeURIComponent('%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F')}\n`;
            else socks5List += `\n  ${go2Socks5s.join('\n  ')}\n`;
        }

        let subscriber = '';
        if (sub) {
            if (enableSocks) subscriber += `CFCDN (access method): Socks5\n  ${newSocks5s.join('\n  ')}\n${socks5List}`;
            else if (proxyIP && proxyIP != '') subscriber += `CFCDN (access method): ProxyIP\n  ${proxyIPs.join('\n  ')}\n`;
            else if (RproxyIP == 'true') subscriber += `CFCDN (access method): Auto-obtain ProxyIP\n`;
            else subscriber += `CFCDN (access method): Cannot access, you need to set proxyIP/PROXYIP!!!\n`
            subscriber += `\nSUB (preferred subscription generator): ${sub}`;
        } else {
            if (enableSocks) subscriber += `CFCDN (access method): Socks5\n  ${newSocks5s.join('\n  ')}\n${socks5List}`;
            else if (proxyIP && proxyIP != '') subscriber += `CFCDN (access method): ProxyIP\n  ${proxyIPs.join('\n  ')}\n`;
            else subscriber += `CFCDN (access method): Cannot access, you need to set proxyIP/PROXYIP!!!\n`;
            subscriber += `\nYour subscription content is provided by the built-in addresses/ADD* parameter variables\n`;
            if (addresses.length > 0) subscriber += `ADD (TLS preferred domain & IP): \n  ${addresses.join('\n  ')}\n`;
            if (addressesapi.length > 0) subscriber += `ADDAPI (TLS preferred domain & IP API): \n  ${addressesapi.join('\n  ')}\n`;
            if (addressescsv.length > 0) subscriber += `ADDCSV (IPTest speed test csv file, speed limit ${DLS}): \n  ${addressescsv.join('\n  ')}\n`;
        }

        return `
################################################################
Subscribe / sub subscription address, supports Base64, clash-meta, sing-box subscription formats
---------------------------------------------------------------
Quick adaptive subscription address:
https://${proxyhost}${hostName}/${password}
https://${proxyhost}${hostName}/${password}?sub

Base64 subscription address:
https://${proxyhost}${hostName}/${password}?b64
https://${proxyhost}${hostName}/${password}?base64

clash subscription address:
https://${proxyhost}${hostName}/${password}?clash

singbox subscription address:
https://${proxyhost}${hostName}/${password}?sb
https://${proxyhost}${hostName}/${password}?singbox

${surge}
---------------------------------------------------------------
################################################################
${FileName} configuration information
---------------------------------------------------------------
HOST: ${hostName}
PASSWORD: ${password}
SHA224: ${sha224Password}
FAKEPASS: ${fakeUserID}
UA: ${UA}

${subscriber}
SUBAPI (subscription conversion backend): ${subProtocol}://${subConverter}
SUBCONFIG (subscription conversion configuration file): ${subConfig}
---------------------------------------------------------------
################################################################
v2ray
---------------------------------------------------------------
${v2ray}
---------------------------------------------------------------
################################################################
clash-meta
---------------------------------------------------------------
${clash}
---------------------------------------------------------------
################################################################
${decodeURIComponent(atob(`dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhCmh0dHBzJTNBJTJGJTJGdC5tZSUyRkNNTGl1c3NzcwotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISEKaHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGY21saXUlMkZlcGVpdXMKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMyUyMw==`))}
`;
    } else {
        if (typeof fetch != 'function') {
            return 'Error: fetch is not available in this environment.';
        }
        // If using the default domain, change it to a workers domain, the subscriber will add a proxy
        if (hostName.includes(".workers.dev")) {
            fakeHostName = `${fakeHostName}.workers.dev`;
        } else {
            fakeHostName = `${fakeHostName}.xyz`
        }

        let url = `https://${sub}/sub?host=${fakeHostName}&pw=${fakeUserID}&password=${fakeUserID + atob('JmVwZWl1cz1jbWxpdSZwcm94eWlwPQ==') + RproxyIP}&path=${encodeURIComponent(path)}`;
        let isBase64 = true;
        let newAddressesapi = [];
        let newAddressescsv = [];

        if (!sub || sub == "") {
            if (hostName.includes('workers.dev')) {
                if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
                    try {
                        const response = await fetch(proxyhostsURL);

                        if (!response.ok) {
                            console.error('Error fetching addresses:', response.status, response.statusText);
                            return; // If there is an error, return directly
                        }

                        const text = await response.text();
                        const lines = text.split('\n');
                        // Filter out empty lines or lines containing only whitespace
                        const nonEmptyLines = lines.filter(line => line.trim() !== '');

                        proxyhosts = proxyhosts.concat(nonEmptyLines);
                    } catch (error) {
                        console.error('Error fetching addresses:', error);
                    }
                }
                // Use Set object to deduplicate
                proxyhosts = [...new Set(proxyhosts)];
            }

            newAddressesapi = await getAddressesapi(addressesapi);
            newAddressescsv = await getAddressescsv('TRUE');
            url = `https://${hostName}/${fakeUserID + _url.search}`;
        }

        if (!userAgent.includes(('CF-Workers-SUB').toLowerCase())) {
            if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || (_url.searchParams.has('clash'))) {
                url = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            } else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || _url.searchParams.has('singbox') || _url.searchParams.has('sb')) {
                url = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            } else if (userAgent.includes('surge') || _url.searchParams.has('surge')) {
                url = `${subProtocol}://${subConverter}/sub?target=surge&ver=4&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&xudp=false&udp=false&tfo=false&expand=true&scv=true&fdn=false`;
                isBase64 = false;
            }
        }

        try {
            let content;
            if ((!sub || sub == "") && isBase64 == true) {
                content = await subAddresses(fakeHostName, fakeUserID, userAgent, newAddressesapi, newAddressescsv);
            } else {
                const response = await fetch(url, {
                    headers: {
                        'User-Agent': atob('Q0YtV29ya2Vycy1lcGVpdXMvY21saXU='),
                    }
                });
                content = await response.text();
            }

            if (_url.pathname == `/${fakeUserID}`) return content;

            content = revertFakeInfo(content, password, hostName, isBase64);
            if (userAgent.includes('surge') || _url.searchParams.has('surge')) content = surge(content, `https://${hostName}/${password}?surge`);
            return content;
        } catch (error) {
            console.error('Error fetching content:', error);
            return `Error fetching content: ${error.message}`;
        }
    }
}

async function sendMessage(type, ip, add_data = "") {
    if (BotToken !== '' && ChatID !== '') {
        let msg = "";
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        if (response.status == 200) {
            const ipInfo = await response.json();
            msg = `${type}\nIP: ${ip}\nCountry: ${ipInfo.country}\n<tg-spoiler>City: ${ipInfo.city}\nOrganization: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
        } else {
            msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
        }

        let url = "https://api.telegram.org/bot" + BotToken + "/sendMessage?chat_id=" + ChatID + "&parse_mode=HTML&text=" + encodeURIComponent(msg);
        return fetch(url, {
            method: 'get',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
            }
        });
    }
}

/**
 *
 * @param {number} addressType
 * @param {string} addressRemote
 * @param {number} portRemote
 * @param {function} log The logging function.
 */
async function socks5Connect(addressType, addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    // Connect to the SOCKS server
    const socket = connect({
        hostname,
        port,
    });

    // Request head format (Worker -> Socks Server):
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+

    // https://en.wikipedia.org/wiki/SOCKS#SOCKS5
    // For METHODS:
    // 0x00 NO AUTHENTICATION REQUIRED
    // 0x02 USERNAME/PASSWORD https://datatracker.ietf.org/doc/html/rfc1929
    const socksGreeting = new Uint8Array([5, 2, 0, 2]);

    const writer = socket.writable.getWriter();

    await writer.write(socksGreeting);
    log('sent socks greeting');

    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    let res = (await reader.read()).value;
    // Response format (Socks Server -> Worker):
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    if (res[0] !== 0x05) {
        log(`socks server version error: ${res[0]} expected: 5`);
        return;
    }
    if (res[1] === 0xff) {
        log("no acceptable methods");
        return;
    }

    // if return 0x0502
    if (res[1] === 0x02) {
        log("socks server needs auth");
        if (!username || !password) {
            log("please provide username/password");
            return;
        }
        // +----+------+----------+------+----------+
        // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        // +----+------+----------+------+----------+
        // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        // +----+------+----------+------+----------+
        const authRequest = new Uint8Array([
            1,
            username.length,
            ...encoder.encode(username),
            password.length,
            ...encoder.encode(password)
        ]);
        await writer.write(authRequest);
        res = (await reader.read()).value;
        // expected 0x0100
        if (res[0] !== 0x01 || res[1] !== 0x00) {
            log("fail to auth socks server");
            return;
        }
    }

    // Request data format (Worker -> Socks Server):
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    // ATYP: address type of following address
    // 0x01: IPv4 address
    // 0x03: Domain name
    // 0x04: IPv6 address
    // DST.ADDR: desired destination address
    // DST.PORT: desired destination port in network octet order

    // addressType
    // 0x01: IPv4 address
    // 0x03: Domain name
    // 0x04: IPv6 address
    // 1--> ipv4  addressLength =4
    // 2--> domain name
    // 3--> ipv6  addressLength =16
    let DSTADDR; // DSTADDR = ATYP + DST.ADDR
    switch (addressType) {
        case 1:
            DSTADDR = new Uint8Array(
                [1, ...addressRemote.split('.').map(Number)]
            );
            break;
        case 3:
            DSTADDR = new Uint8Array(
                [3, addressRemote.length, ...encoder.encode(addressRemote)]
            );
            break;
        case 4:
            DSTADDR = new Uint8Array(
                [4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
            );
            break;
        default:
            log(`invalid addressType is ${addressType}`);
            return;
    }
    const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    await writer.write(socksRequest);
    log('sent socks request');

    res = (await reader.read()).value;
    // Response format (Socks Server -> Worker):
    //  +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    if (res[1] === 0x00) {
        log("socks connection opened");
    } else {
        log("fail to open socks connection");
        return;
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

/**
 *
 * @param {string} address
 */
function socks5AddressParser(address) {
    let [latter, former] = address.split("@").reverse();
    let username, password, hostname, port;
    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('Invalid SOCKS address format');
        }
        [username, password] = formers;
    }
    const latters = latter.split(":");
    port = Number(latters.pop());
    if (isNaN(port)) {
        throw new Error('Invalid SOCKS address format');
    }
    hostname = latters.join(":");
    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('Invalid SOCKS address format');
    }
    //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
    return {
        username,
        password,
        hostname,
        port,
    }
}

function isValidIPv4(address) {
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(address);
}

function subAddresses(host, pw, userAgent, newAddressesapi, newAddressescsv) {
    addresses = addresses.concat(newAddressesapi);
    addresses = addresses.concat(newAddressescsv);
    // Use Set object to deduplicate
    const uniqueAddresses = [...new Set(addresses)];

    const responseBody = uniqueAddresses.map(address => {
        let port = "-1";
        let addressid = address;

        const match = addressid.match(regex);
        if (!match) {
            if (address.includes(':') && address.includes('#')) {
                const parts = address.split(':');
                address = parts[0];
                const subParts = parts[1].split('#');
                port = subParts[0];
                addressid = subParts[1];
            } else if (address.includes(':')) {
                const parts = address.split(':');
                address = parts[0];
                port = parts[1];
            } else if (address.includes('#')) {
                const parts = address.split('#');
                address = parts[0];
                addressid = parts[1];
            }

            if (addressid.includes(':')) {
                addressid = addressid.split(':')[0];
            }
        } else {
            address = match[1];
            port = match[2] || port;
            addressid = match[3] || address;
        }

        const httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
        if (!isValidIPv4(address) && port == "-1") {
            for (let httpsPort of httpsPorts) {
                if (address.includes(httpsPort)) {
                    port = httpsPort;
                    break;
                }
            }
        }
        if (port == "-1") port = "443";

        let disguisedDomain = host;
        let finalPath = path;
        let nodeRemark = '';

        if (proxyhosts.length > 0 && (disguisedDomain.includes('.workers.dev'))) {
            finalPath = `/${disguisedDomain}${finalPath}`;
            disguisedDomain = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
            nodeRemark = ` Temporary domain forwarding service enabled, please bind a custom domain as soon as possible!`;
        }
        const matchingProxyIP = proxyIPPool.find(proxyIP => proxyIP.includes(address));
        if (matchingProxyIP) finalPath += `&proxyip=${matchingProxyIP}`;
        let password = pw;
        if (!userAgent.includes('subconverter')) password = encodeURIComponent(pw);

        const 啥啥啥_写的这是啥啊 = 'dHJvamFu';
        const protocolType = atob(啥啥啥_写的这是啥啊);
        const trojanLink = `${protocolType}://${password}@${address}:${port}?security=tls&sni=${disguisedDomain}&fp=randomized&type=ws&host=${disguisedDomain}&path=${encodeURIComponent(finalPath)}#${encodeURIComponent(addressid + nodeRemark)}`;

        return trojanLink;
    }).join('\n');

    const base64Response = btoa(responseBody); // Re-encode in Base64

    return base64Response;
}

async function getAddressesapi(api) {
    if (!api || api.length === 0) return [];
    let newapi = "";

    // Create an AbortController object to control the cancellation of fetch requests
    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort(); // Cancel all requests
    }, 2000); // Trigger after 2 seconds

    try {
        // Use Promise.allSettled to wait for all API requests to complete, whether they succeed or fail
        // Iterate over the api array and make a fetch request for each API address
        const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
            method: 'get',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'User-Agent': atob('Q0YtV29ya2Vycy1lcGVpdXMvY21saXU=')
            },
            signal: controller.signal // Add the AbortController signal to the fetch request to cancel the request if needed
        }).then(response => response.ok ? response.text() : Promise.reject())));

        // Iterate over all responses
        for (const [index, response] of responses.entries()) {
            // Check if the response status is 'fulfilled', i.e., the request completed successfully
            if (response.status === 'fulfilled') {
                // Get the content of the response
                const content = await response.value;

                const lines = content.split(/\r?\n/);
                let nodeRemark = '';
                let testPort = '443';
                if (lines[0].split(',').length > 3) {
                    const idMatch = api[index].match(/id=([^&]*)/);
                    if (idMatch) nodeRemark = idMatch[1];
                    const portMatch = api[index].match(/port=([^&]*)/);
                    if (portMatch) testPort = portMatch[1];

                    for (let i = 1; i < lines.length; i++) {
                        const columns = lines[i].split(',')[0];
                        if (columns) {
                            newapi += `${columns}:${testPort}${nodeRemark ? `#${nodeRemark}` : ''}\n`;
                            if (api[index].includes('proxyip=true')) proxyIPPool.push(`${columns}:${testPort}`);
                        }
                    }
                } else {
                    // Verify if the current apiUrl contains 'proxyip=true'
                    if (api[index].includes('proxyip=true')) {
                        // If the URL contains 'proxyip=true', add the content to proxyIPPool
                        proxyIPPool = proxyIPPool.concat((await ADD(content)).map(item => {
                            const baseItem = item.split('#')[0] || item;
                            if (baseItem.includes(':')) {
                                const port = baseItem.split(':')[1];
                                if (!httpsPorts.includes(port)) {
                                    return baseItem;
                                }
                            } else {
                                return `${baseItem}:443`;
                            }
                            return null; // Return null if the condition is not met
                        }).filter(Boolean)); // Filter out null values
                    }
                    // Add the content to newapi
                    newapi += content + '\n';
                }
            }
        }
    } catch (error) {
        console.error(error);
    } finally {
        // Clear the timeout regardless of success or failure
        clearTimeout(timeout);
    }

    const newAddressesapi = await ADD(newapi);

    // Return the processed result
    return newAddressesapi;
}

async function getAddressescsv(tls) {
    if (!addressescsv || addressescsv.length === 0) {
        return [];
    }

    let newAddressescsv = [];

    for (const csvUrl of addressescsv) {
        try {
            const response = await fetch(csvUrl);

            if (!response.ok) {
                console.error('Error fetching CSV address:', response.status, response.statusText);
                continue;
            }

            const text = await response.text(); // Parse the text content with the correct character encoding
            let lines;
            if (text.includes('\r\n')) {
                lines = text.split('\r\n');
            } else {
                lines = text.split('\n');
            }

            // Check if the CSV header contains the required fields
            const header = lines[0].split(',');
            const tlsIndex = header.indexOf('TLS');

            const ipAddressIndex = 0; // Position of the IP address in the CSV header
            const portIndex = 1; // Position of the port in the CSV header
            const dataCenterIndex = tlsIndex + remarkIndex; // Data center is the field after TLS

            if (tlsIndex === -1) {
                console.error('CSV file is missing required fields');
                continue;
            }

            // Iterate over the CSV rows starting from the second row
            for (let i = 1; i < lines.length; i++) {
                const columns = lines[i].split(',');
                const speedIndex = columns.length - 1; // Last field
                // Check if TLS is "TRUE" and speed is greater than DLS
                if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
                    const ipAddress = columns[ipAddressIndex];
                    const port = columns[portIndex];
                    const dataCenter = columns[dataCenterIndex];

                    const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
                    newAddressescsv.push(formattedAddress);
                    if (csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() == 'true' && !httpsPorts.includes(port)) {
                        // If the URL contains 'proxyip=true', add the content to proxyIPPool
                        proxyIPPool.push(`${ipAddress}:${port}`);
                    }
                }
            }
        } catch (error) {
            console.error('Error fetching CSV address:', error);
            continue;
        }
    }

    return newAddressescsv;
}

function surge(content, url) {
    let eachLine;
    if (content.includes('\r\n')) {
        eachLine = content.split('\r\n');
    } else {
        eachLine = content.split('\n');
    }

    let outputContent = "";
    for (let x of eachLine) {
        if (x.includes(atob('PSB0cm9qYW4s'))) {
            const host = x.split("sni=")[1].split(",")[0];
            const backupContent = `skip-cert-verify=true, tfo=false, udp-relay=false`;
            const correctContent = `skip-cert-verify=true, ws=true, ws-path=${path}, ws-headers=Host:"${host}", tfo=false, udp-relay=false`;
            outputContent += x.replace(new RegExp(backupContent, 'g'), correctContent).replace("[", "").replace("]", "") + '\n';
        } else {
            outputContent += x + '\n';
        }
    }

    outputContent = `#!MANAGED-CONFIG ${url} interval=86400 strict=false` + outputContent.substring(outputContent.indexOf('\n'));
    return outputContent;
}

/**
 * [js-sha256]{@link https://github.com/emn178/js-sha256}
 *
 * @version 0.11.0 (modified by cmliu)
 * @description This code is based on the js-sha256 project, with the addition of the SHA-224 hash algorithm implementation.
 * @author Chen, Yi-Cyuan [emn178@gmail.com], modified by cmliu
 * @copyright Chen, Yi-Cyuan 2014-2024
 * @license MIT
 *
 * @modifications Rewrote and implemented the sha224 function. Please cite the source when referencing. Modification date: 2024-12-04, Github: cmliu
 */
function sha224(inputString) {
    // Internal constants and functions
    const constantsK = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    function utf8Encode(string) {
        return unescape(encodeURIComponent(string));
    }

    function bytesToHex(byteArray) {
        let hex = '';
        for (let i = 0; i < byteArray.length; i++) {
            hex += ((byteArray[i] >>> 4) & 0x0F).toString(16);
            hex += (byteArray[i] & 0x0F).toString(16);
        }
        return hex;
    }

    function sha224Core(inputString) {
        // Initial hash value for SHA-224
        let hash = [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ];

        // Preprocessing
        const messageLength = inputString.length * 8;
        inputString += String.fromCharCode(0x80);
        while ((inputString.length * 8) % 512 !== 448) {
            inputString += String.fromCharCode(0);
        }

        // 64-bit message length
        const messageLengthHigh = Math.floor(messageLength / 0x100000000);
        const messageLengthLow = messageLength & 0xFFFFFFFF;
        inputString += String.fromCharCode(
            (messageLengthHigh >>> 24) & 0xFF, (messageLengthHigh >>> 16) & 0xFF,
            (messageLengthHigh >>> 8) & 0xFF, messageLengthHigh & 0xFF,
            (messageLengthLow >>> 24) & 0xFF, (messageLengthLow >>> 16) & 0xFF,
            (messageLengthLow >>> 8) & 0xFF, messageLengthLow & 0xFF
        );

        const wordArray = [];
        for (let i = 0; i < inputString.length; i += 4) {
            wordArray.push(
                (inputString.charCodeAt(i) << 24) |
                (inputString.charCodeAt(i + 1) << 16) |
                (inputString.charCodeAt(i + 2) << 8) |
                inputString.charCodeAt(i + 3)
            );
        }

        // Main compression loop
        for (let i = 0; i < wordArray.length; i += 16) {
            const w = new Array(64).fill(0);
            for (let j = 0; j < 16; j++) {
                w[j] = wordArray[i + j];
            }

            for (let j = 16; j < 64; j++) {
                const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
            }

            let [a, b, c, d, e, f, g, h0] = hash;

            for (let j = 0; j < 64; j++) {
                const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
                const ch = (e & f) ^ (~e & g);
                const temp1 = (h0 + S1 + ch + constantsK[j] + w[j]) >>> 0;
                const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const temp2 = (S0 + maj) >>> 0;

                h0 = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }

            hash[0] = (hash[0] + a) >>> 0;
            hash[1] = (hash[1] + b) >>> 0;
            hash[2] = (hash[2] + c) >>> 0;
            hash[3] = (hash[3] + d) >>> 0;
            hash[4] = (hash[4] + e) >>> 0;
            hash[5] = (hash[5] + f) >>> 0;
            hash[6] = (hash[6] + g) >>> 0;
            hash[7] = (hash[7] + h0) >>> 0;
        }

        // Truncate to 224 bits
        return hash.slice(0, 7);
    }

    function rightRotate(value, bits) {
        return ((value >>> bits) | (value << (32 - bits))) >>> 0;
    }

    // Main function logic
    const encodedInput = utf8Encode(inputString);
    const hashResult = sha224Core(encodedInput);

    // Convert to hexadecimal string
    return bytesToHex(
        hashResult.flatMap(h => [
            (h >>> 24) & 0xFF,
            (h >>> 16) & 0xFF,
            (h >>> 8) & 0xFF,
            h & 0xFF
        ])
    );
}
