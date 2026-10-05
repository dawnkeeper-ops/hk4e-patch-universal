use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use crate::util;

// 这两个函数位于 GenshinImpact.exe 的 **il2cpp** 段
// (RVA 0x169da3d0 / 0x16962cc0, file 0x161f73d0 / 0x1617fcc0),不在 .text —
// 用 pattern_scan_code 永远搜不到,必须用 pattern_scan_il2cpp。
const HOYOPASS_LOGINMANAGER_INITIALIZE: &str = "56 57 53 48 83 EC 30 48 89 CE 80 3D 6D FB 7F EE 00 0F 84 2E 03 00 00";
const HOYOPASS_SDK_INITIALIZE: &str = "55 56 57 48 83 EC 70 48 8d 6c 24 70 48 c7 45 f0 fe ff ff ff 48 89 ce 80 3d c3 6e 87 ee 00";

pub struct Hoyopass;

impl MhyModule for MhyContext<Hoyopass> {
    unsafe fn init(&mut self) -> Result<()> {
        // 只做观测(不改返回值):强制 return 0 会让 hoYoPass 登录链路半初始化,
        // 而当前方案是把原生 SDK 的 HTTP 引到本地 dispatch,它必须保持原样。
        let loginmanager = util::pattern_scan_il2cpp(self.assembly_name, HOYOPASS_LOGINMANAGER_INITIALIZE);
        if let Some(addr) = loginmanager {
            crate::plog!("hoyopass_loginmanager_initialize: {:x}", addr as usize);
            if let Err(e) = self.interceptor.attach(addr as usize, on_loginmanager) {
                crate::plog!("attach hoyopass_loginmanager_initialize failed: {e}");
            }
        }
        else
        {
            crate::plog!("Failed to find hoyopass_loginmanager_initialize");
        }

        let sdk_init = util::pattern_scan_il2cpp(self.assembly_name, HOYOPASS_SDK_INITIALIZE);
        if let Some(addr) = sdk_init {
            crate::plog!("hoyopass_sdk_initialize: {:x}", addr as usize);
            if let Err(e) = self.interceptor.attach(addr as usize, on_sdk_init) {
                crate::plog!("attach hoyopass_sdk_initialize failed: {e}");
            }
        }
        else
        {
            crate::plog!("Failed to find hoyopass_sdk_initialize");
        }

        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Hoyopass
    }
}

unsafe extern "win64" fn on_loginmanager(
    _: *mut Registers,
    _: usize,
) {
    crate::plog!("[hoyopass] loginmanager_initialize called");
}

unsafe extern "win64" fn on_sdk_init(
    _: *mut Registers,
    _: usize,
) {
    crate::plog!("[hoyopass] sdk_initialize called");
}
