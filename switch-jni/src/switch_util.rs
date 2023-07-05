use std::net::ToSocketAddrs;
use std::ptr;

use jni::errors::Error;
use jni::objects::{JClass, JObject, JString, JValue};
#[cfg(not(target_os = "android"))]
use jni::sys::jboolean;
use jni::sys::{jint, jlong, jobject};
use jni::JNIEnv;
use switch::core::Config;
use switch::core::sync::SwitchUtilSync;
use switch::handle::registration_handler::{RegResponse, ReqEnum};
#[cfg(not(target_os = "android"))]
use switch::tun_tap_device::DriverInfo;

fn to_string_not_null(env: &mut JNIEnv, config: &JObject, name: &'static str) -> Result<String, Error> {
    let value = env.get_field(config, name, "Ljava/lang/String;")?.l()?;
    if value.is_null() {
        env.throw_new("Ljava/lang/NullPointerException", name)
            .expect("throw");
        return Err(Error::NullPtr(name));
    }
    let binding = JString::from(value);
    let value = env.get_string(binding.as_ref())?;
    match value.to_str() {
        Ok(value) => Ok(value.to_string()),
        Err(_) => {
            env.throw_new("Ljava/lang/RuntimeException", "not utf-8")
                .expect("throw");
            return Err(Error::JavaException);
        }
    }
}

fn to_string(env: &mut JNIEnv, config: &JObject, name: &str) -> Result<Option<String>, Error> {
    let value = env.get_field(config, name, "Ljava/lang/String;")?.l()?;
    if value.is_null() {
        return Ok(None);
    }
    let tmp = JString::from(value);
    let value = env.get_string(tmp.as_ref())?;
    match value.to_str() {
        Ok(value) => Ok(Some(value.to_string())),
        Err(_) => {
            env.throw_new("Ljava/lang/RuntimeException", "not utf-8")
                .expect("throw");
            return Err(Error::JavaException);
        }
    }
}

fn new_sync(env: &mut JNIEnv, config: JObject) -> Result<SwitchUtilSync, Error> {
    let token = to_string_not_null(env, &config, "token")?;
    let name = to_string_not_null(env, &config, "name")?;
    let device_id = to_string_not_null(env, &config, "deviceId")?;
    let server = to_string_not_null(env, &config, "server")?;
    let nat_test_server = to_string_not_null(env, &config, "natTestServer")?;
    let server_address = match server.to_socket_addrs() {
        Ok(mut rs) => {
            if let Some(addr) = rs.next() {
                addr
            } else {
                env.throw_new("Ljava/lang/RuntimeException", "server address err")
                    .expect("throw");
                return Err(Error::JavaException);
            }
        }
        Err(e) => {
            env.throw_new("Ljava/lang/RuntimeException", format!("server address {}", e))
                .expect("throw");
            return Err(Error::JavaException);
        }
    };
    let nat_test_server = nat_test_server.split(",").flat_map(|a| a.trim().to_socket_addrs()).flatten()
        .collect::<Vec<_>>();
    let config = Config::new(false,
                             token, device_id, name,
                             server_address,
                             nat_test_server, vec![],
                             vec![], None, false, );
    match SwitchUtilSync::new(config) {
        Ok(switch_util) => {
            Ok(switch_util)
        }
        Err(e) => {
            env.throw_new("Ljava/lang/RuntimeException", format!("switch start error {}", e))
                .expect("throw");
            return Err(Error::JavaException);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_switchjni_SwitchUtil_new0(
    mut env: JNIEnv,
    _class: JClass,
    config: JObject,
) -> jlong {
    match new_sync(&mut env, config) {
        Ok(switch_util) => {
            let ptr = Box::into_raw(Box::new(switch_util));
            return ptr as jlong;
        }
        Err(_) => {}
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_switchjni_SwitchUtil_connect0(
    mut env: JNIEnv,
    _class: JClass,
    raw_switch_util: jlong,
) -> jobject {
    let raw_switch_util = raw_switch_util as *mut SwitchUtilSync;
    match (&mut *raw_switch_util).connect() {
        Ok(response) => {
            match reg_response(&mut env, response) {
                Ok(res) => {
                    return res;
                }
                Err(e) => {
                    env.throw(format!("switch connect error {}", e)).expect("throw");
                }
            }
        }
        Err(e) => {
            match e {
                ReqEnum::TokenError => {
                    env.throw_new("top/wherewego/switchjni/exception/TokenErrorException", "TokenError")
                        .expect("throw");
                }
                ReqEnum::AddressExhausted => {
                    env.throw_new("top/wherewego/switchjni/exception/AddressExhaustedException", "AddressExhausted")
                        .expect("throw");
                }
                ReqEnum::Timeout => {
                    env.throw_new("top/wherewego/switchjni/exception/TimeoutException", "Timeout")
                        .expect("throw");
                }
                ReqEnum::ServerError(str) => {
                    env.throw_new("java/lang/RuntimeException", format!("switch connect error {}", str))
                        .expect("throw");
                }
                ReqEnum::Other(str) => {
                    env.throw_new("java/lang/RuntimeException", format!("switch connect error {}", str))
                        .expect("throw");
                }
            }
        }
    }
    return ptr::null_mut();
}

#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_switchjni_SwitchUtil_createIface0(
    _env: JNIEnv,
    _class: JClass,
    raw_switch_util: jlong,
    fd: jint,
) {
    let raw_switch_util = raw_switch_util as *mut SwitchUtilSync;

    (&mut *raw_switch_util).create_iface(fd as i32);
}

#[cfg(not(target_os = "android"))]
#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_switchjni_SwitchUtil_createIface0(
    mut env: JNIEnv,
    _class: JClass,
    raw_switch_util: jlong,
) -> jobject {
    let raw_switch_util = raw_switch_util as *mut SwitchUtilSync;
    #[cfg(not(target_os = "android"))]
        let rs = (&mut *raw_switch_util).create_iface();
    match rs {
        Ok(driver_info) => {
            match driver_info_e(&mut env, driver_info) {
                Ok(res) => {
                    return res;
                }
                Err(e) => {
                    env.throw(format!("switch create iface  error {}", e)).expect("throw");
                }
            }
        }
        Err(e) => {
            env.throw_new("java/lang/RuntimeException", format!("switch create iface error {}", e))
                .expect("throw");
        }
    }
    return ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_switchjni_SwitchUtil_build0(
    mut env: JNIEnv,
    _class: JClass,
    raw_switch_util: jlong,
) -> jlong {
    let raw_switch_util = Box::from_raw(raw_switch_util as *mut SwitchUtilSync);
    match raw_switch_util.build() {
        Ok(rs) => {
            return Box::into_raw(Box::new(rs)) as jlong;
        }
        Err(e) => {
            env.throw_new("java/lang/RuntimeException", format!("switch start error:{:?}", e))
                .expect("throw");
        }
    }
    return 0;
}

fn reg_response(env: &mut JNIEnv, response: RegResponse) -> Result<jobject, Error> {
    let virtual_ip = u32::from(response.virtual_ip);
    let virtual_gateway = u32::from(response.virtual_gateway);
    let virtual_netmask = u32::from(response.virtual_netmask);
    let response = env.new_object(
        "top/wherewego/switchjni/RegResponse",
        "(III)V",
        &[JValue::Int(virtual_ip as jint),
            JValue::Int(virtual_gateway as jint),
            JValue::Int(virtual_netmask as jint)],
    )?;
    Ok(response.into_raw())
}

#[cfg(not(target_os = "android"))]
fn driver_info_e(env: &mut JNIEnv, driver_info: DriverInfo) -> Result<jobject, Error> {
    let is_tun = driver_info.device_type.is_tun();
    let name = driver_info.name;
    let version = driver_info.version;
    let mac = driver_info.mac.unwrap_or(String::new());
    let response = env.new_object(
        "top/wherewego/switchjni/DriverInfo",
        "(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        &[JValue::Bool(is_tun as jboolean),
            JValue::Object(&env.new_string(name)?.into()),
            JValue::Object(&env.new_string(version)?.into()),
            JValue::Object(&env.new_string(mac)?.into()), ],
    )?;
    Ok(response.into_raw())
}
