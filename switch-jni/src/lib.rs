use std::net::{IpAddr, Ipv4Addr};


use jni::errors::Error;
use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jbyte, jint, jintArray, jlong, jobject, jsize};
use jni::JNIEnv;

use switch::handle::{CurrentDeviceInfo, Route};
use switch::{Config, Switch};

fn to_string(env: &JNIEnv, config: JObject, name: &str) -> Result<Option<String>, Error> {
    let value = env.get_field(config, name, "Ljava/lang/String;")?.l()?;
    if value.is_null() {
        env.throw_new("Ljava/lang/NullPointerException", &name)
            .expect("throw");
        return Ok(None);
    }
    let value = env.get_string(JString::from(value))?;
    match value.to_str() {
        Ok(value) => Ok(Some(value.to_string())),
        Err(_) => {
            env.throw_new("Ljava/lang/RuntimeException", "not utf-8")
                .expect("throw");
            Ok(None)
        }
    }
}

fn start(env: &JNIEnv, config: JObject) -> Result<Option<Switch>, Error> {
    if let Some(token) = to_string(&env, config, "token")? {
        if let Some(mac_address) = to_string(&env, config, "macAddress")? {
            match Switch::start(Config::new(token, mac_address)) {
                Ok(switch) => {
                    return Ok(Some(switch));
                }
                Err(e) => {
                    env.throw_new(
                        "Ljava/lang/RuntimeException",
                        format!("switch start failed {:?}", e),
                    )
                    .expect("throw");
                }
            }
        }
    }
    Ok(None)
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_switches_jni_Switch_start0(
    env: JNIEnv,
    _class: JClass,
    config: JObject,
) -> jlong {
    match start(&env, config) {
        Ok(switch) => {
            if let Some(switch) = switch {
                return Box::into_raw(Box::new(switch)) as jlong;
            }
        }
        Err(_) => {}
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_switches_jni_Switch_stop0(
    _env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
) {
    let switch = Box::from_raw(raw_switch as *mut Switch);
    switch.stop();
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_switches_jni_Switch_currentDevice0(
    env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
) -> jobject {
    let switch = raw_switch as *mut Switch;
    let dev_info = (&*switch).current_device();
    match current_device(&env, dev_info) {
        Ok(obj) => obj,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_switches_jni_Switch_deviceList0(
    env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
) -> jintArray {
    let switch = raw_switch as *mut Switch;
    match device_list(&env, (&*switch).device_list()) {
        Ok(arr) => arr,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_switches_jni_Switch_route0(
    env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
    ip: jint,
) -> jobject {
    let ip = Ipv4Addr::from(ip as u32);
    let switch = raw_switch as *mut Switch;
    match route(&env, (&*switch).route(&ip)) {
        Ok(arr) => arr,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_switches_jni_Switch_serverRt0(
    _env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
) -> jlong {
    let switch = raw_switch as *mut Switch;
    let rt = (&*switch).server_rt();
    rt as jlong
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_switches_jni_Switch_connectionStatus0(
    _env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
) -> jbyte {
    let switch = raw_switch as *mut Switch;
    let connection_status: u8 = (&*switch).connection_status().into();
    connection_status as jbyte
}

fn route(env: &JNIEnv, route: Route) -> Result<jobject, Error> {
    let route_type: u8 = route.route_type.into();
    let rt = route.rt;
    let route = env.new_object(
        "org/switches/jni/Route",
        "(BJ)V",
        &[JValue::Byte(route_type as jbyte), JValue::Long(rt as jlong)],
    )?;
    Ok(route.into_raw())
}

fn device_list(env: &JNIEnv, device_list: Vec<Ipv4Addr>) -> Result<jintArray, Error> {
    if device_list.is_empty() {
        return Ok(std::ptr::null_mut());
    }
    let arr = env.new_int_array(device_list.len() as jsize)?;
    let devices: Vec<jint> = device_list
        .iter()
        .map(|ip| {
            let ip: u32 = (*ip).into();
            ip as jint
        })
        .collect();
    env.set_int_array_region(arr, 0, &devices)?;
    Ok(arr)
}

fn current_device(env: &JNIEnv, dev_info: &CurrentDeviceInfo) -> Result<jobject, Error> {
    let virtual_ip: u32 = dev_info.virtual_ip.into();
    let virtual_gateway: u32 = dev_info.virtual_gateway.into();
    let virtual_netmask: u32 = dev_info.virtual_netmask.into();
    let virtual_network: u32 = dev_info.virtual_network.into();
    let broadcast_address: u32 = dev_info.broadcast_address.into();
    let connect_server_host: u32 = match dev_info.connect_server.ip() {
        IpAddr::V4(ip) => ip.into(),
        IpAddr::V6(_) => {
            panic!()
        }
    };
    let connect_server_port = dev_info.connect_server.port() as u32;
    let current_device = env.new_object(
        "org/switches/jni/CurrentDevice",
        "(IIIIIII)V",
        &[
            JValue::Int(virtual_ip as jint),
            JValue::Int(virtual_gateway as jint),
            JValue::Int(virtual_netmask as jint),
            JValue::Int(virtual_network as jint),
            JValue::Int(broadcast_address as jint),
            JValue::Int(connect_server_host as jint),
            JValue::Int(connect_server_port as jint),
        ],
    )?;
    Ok(current_device.into_raw())
}
