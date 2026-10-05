use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::core::s;

// 6.6 客户端的“账号密码登录”由原生账号 SDK 发起 (GenshinImpact_Data/Plugins/HYPass.dll
// 导入 WinHttpOpen / WinHttpConnect / WinHttpSendRequest,AccountPlatNative.dll 里还有
// libcurl),URL 由游戏从 resources.assets 交给 SDK,例如
//   https://hk4e-sdk-os.hoyoverse.com/hk4e_global/account/ma-passport/api/appLoginByPassword
// 这条流量不经过 il2cpp 的 web_request_utils_make_initial_url(补丁唯一改写的那个函数),
// 所以补丁日志里看不到它的 Redirect,请求直接发往真实域名 → 秒挂 NetworkError。
//
// 这里直接在 winhttp.dll 的导出函数上挂钩,把命运之host改成 127.0.0.1:8088 并去掉 TLS 标志,
// 于是账号 SDK 的登录请求会打到本地 dispatch(LunaGC-6.6 已实现 ma-passport 登录路由)。
const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
const LOCAL_PORT: u64 = 8088;

/// L"127.0.0.1"
static LOCAL_HOST: [u16; 10] = [0x31, 0x32, 0x37, 0x2E, 0x30, 0x2E, 0x30, 0x2E, 0x31, 0x0000];

/// 只有已经改过 host 之后,才去掉 TLS 标志(避免影响进程内其它 WinHTTP 使用者)
static REDIRECTED: AtomicBool = AtomicBool::new(false);
static REDIRECT_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

pub struct WinHttp;

impl MhyModule for MhyContext<WinHttp> {
    unsafe fn init(&mut self) -> Result<()> {
        let module = match LoadLibraryA(s!("winhttp.dll")) {
            Ok(module) => module,
            Err(_) => {
                crate::plog!("[WinHttp] Failed to load winhttp.dll");
                return Ok(());
            }
        };

        match GetProcAddress(module, s!("WinHttpConnect")) {
            Some(proc) => {
                let addr = proc as usize;
                crate::plog!("WinHttpConnect: {addr:x}");
                if let Err(e) = self.interceptor.attach(addr, on_winhttp_connect) {
                    crate::plog!("[WinHttp] attach WinHttpConnect failed: {e}");
                }
            }
            None => crate::plog!("[WinHttp] Failed to resolve WinHttpConnect"),
        }

        match GetProcAddress(module, s!("WinHttpOpenRequest")) {
            Some(proc) => {
                let addr = proc as usize;
                crate::plog!("WinHttpOpenRequest: {addr:x}");
                if let Err(e) = self.interceptor.attach(addr, on_winhttp_open_request) {
                    crate::plog!("[WinHttp] attach WinHttpOpenRequest failed: {e}");
                }
            }
            None => crate::plog!("[WinHttp] Failed to resolve WinHttpOpenRequest"),
        }

        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::WinHttp
    }
}

// WinHttpConnect(HINTERNET hSession[rcx], LPCWSTR pswzServerName[rdx],
//                INTERNET_PORT nServerPort[r8], DWORD dwReserved[r9])
unsafe extern "win64" fn on_winhttp_connect(reg: *mut Registers, _: usize) {
    let ptr = (*reg).rdx as *const u16;
    if ptr.is_null() {
        return;
    }

    let mut len = 0usize;
    while len < 128 && *ptr.add(len) != 0 {
        len += 1;
    }
    if len == 0 || len >= 128 {
        return;
    }

    let host = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len)).to_ascii_lowercase();
    if !is_hoyo_host(&host) {
        return;
    }

    let n = REDIRECT_LOG_COUNT.fetch_add(1, Ordering::SeqCst);
    if n < 40 {
        crate::plog!("[WinHttp] redirect {host}:{} -> 127.0.0.1:8088", (*reg).r8);
    }

    (*reg).rdx = LOCAL_HOST.as_ptr() as u64;
    (*reg).r8 = LOCAL_PORT;
    REDIRECTED.store(true, Ordering::SeqCst);
}

// WinHttpOpenRequest(hConnect[rcx], pwszVerb[rdx], pwszObjectName[r8], pwszVersion[r9],
//                   pwszReferrer[stack+0x28], ppwszAcceptTypes[stack+0x30], dwFlags[stack+0x38])
unsafe extern "win64" fn on_winhttp_open_request(reg: *mut Registers, _: usize) {
    if !REDIRECTED.load(Ordering::SeqCst) {
        return;
    }

    let flags = (*reg).get_stack(7) as u32;
    if flags & WINHTTP_FLAG_SECURE == 0 {
        return;
    }

    let new_flags = flags & !WINHTTP_FLAG_SECURE;
    *(((*reg).rsp as usize + 0x38) as *mut u32) = new_flags;

    let n = REDIRECT_LOG_COUNT.fetch_add(1, Ordering::SeqCst);
    if n < 80 {
        crate::plog!("[WinHttp] strip TLS flag: 0x{flags:08x} -> 0x{new_flags:08x}");
    }
}

fn is_hoyo_host(host: &str) -> bool {
    const SUFFIXES: [&str; 4] = ["hoyoverse.com", "mihoyo.com", "yuanshen.com", "hoyolab.com"];
    SUFFIXES.iter().any(|suffix| host == *suffix || host.ends_with(suffix))
}
