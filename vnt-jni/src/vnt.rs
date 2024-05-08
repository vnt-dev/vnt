use std::ptr;
use std::time::Duration;

use jni::errors::Error;
use jni::objects::{JClass, JObject, JValue};
use jni::sys::{jboolean, jint, jlong, jobject, jobjectArray, jsize};
use jni::JNIEnv;

use vnt::channel::Route;
use vnt::core::Vnt;
use vnt::handle::PeerDeviceInfo;

use crate::callback::CallBack;

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_vnt_jni_Vnt_new0(
    mut env: JNIEnv<'static>,
    _class: JClass,
    config: JObject,
    call_back: JObject<'static>,
) -> jlong {
    let jvm = if let Ok(jvm) = env.get_java_vm() {
        jvm
    } else {
        return 0;
    };
    match crate::config::new_config(&mut env, config) {
        Ok(config) => {
            let call_back = if let Ok(call_back) = env.new_global_ref(call_back) {
                call_back
            } else {
                return 0;
            };
            let call_back = match CallBack::new(jvm, call_back) {
                Ok(call_back) => call_back,
                Err(_) => {
                    return 0;
                }
            };
            let vnt_util = match Vnt::new(config, call_back) {
                Ok(vnt_util) => vnt_util,
                Err(e) => {
                    env.throw_new(
                        "java/lang/RuntimeException",
                        format!("vnt start error {}", e),
                    )
                    .expect("throw");
                    return 0;
                }
            };
            let ptr = Box::into_raw(Box::new(vnt_util));
            return ptr as jlong;
        }
        Err(_) => {}
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_vnt_jni_Vnt_stop0(
    _env: JNIEnv,
    _class: JClass,
    raw_vnt: jlong,
) {
    let vnt = raw_vnt as *mut Vnt;
    let _ = (&*vnt).stop();
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_vnt_jni_Vnt_wait0(
    _env: JNIEnv,
    _class: JClass,
    raw_vnt: jlong,
) {
    let vnt = raw_vnt as *mut Vnt;
    let _ = (&*vnt).wait();
}
#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_vnt_jni_Vnt_waitTimeout0(
    _env: JNIEnv,
    _class: JClass,
    raw_vnt: jlong,
    time: jlong,
) -> jboolean {
    let vnt = raw_vnt as *mut Vnt;
    (&*vnt).wait_timeout(Duration::from_millis(time as _)) as _
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_vnt_jni_Vnt_drop0(
    _env: JNIEnv,
    _class: JClass,
    raw_vnt: jlong,
) {
    let vnt = raw_vnt as *mut Vnt;
    let _ = Box::from_raw(vnt).stop();
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_vnt_jni_Vnt_list0(
    mut env: JNIEnv,
    _class: JClass,
    raw_vnt: jlong,
) -> jobjectArray {
    let vnt = raw_vnt as *mut Vnt;
    let vnt = &mut *vnt;
    let list = vnt.device_list();

    let arr = match env.new_object_array(
        list.len() as jsize,
        "top/wherewego/vnt/jni/PeerRouteInfo",
        JObject::null(),
    ) {
        Ok(arr) => arr,
        Err(e) => {
            env.throw_new("java/lang/RuntimeException", format!("error:{:?}", e))
                .expect("throw");
            return ptr::null_mut();
        }
    };
    for (index, peer) in list.into_iter().enumerate() {
        let route = if let Some(route) = vnt.route(&peer.virtual_ip) {
            match route_parse(&mut env, route) {
                Ok(route) => JObject::from_raw(route),
                Err(_) => JObject::null(),
            }
        } else {
            JObject::null()
        };
        match peer_device_info_parse(&mut env, peer, route) {
            Ok(peer) => {
                match env.set_object_array_element(&arr, index as jsize, JObject::from_raw(peer)) {
                    Ok(_) => {}
                    Err(e) => {
                        env.throw_new("java/lang/RuntimeException", format!("error:{:?}", e))
                            .expect("throw");
                        return ptr::null_mut();
                    }
                }
            }
            Err(e) => {
                env.throw_new("java/lang/RuntimeException", format!("error:{:?}", e))
                    .expect("throw");
                return ptr::null_mut();
            }
        }
    }
    arr.as_raw()
}

fn route_parse(env: &mut JNIEnv, route: Route) -> Result<jobject, Error> {
    let rs = env.new_object(
        "top/wherewego/vnt/jni/Route",
        "(ZLjava/lang/String;BI)V",
        &[
            JValue::Bool(route.is_tcp as _),
            JValue::Object(&env.new_string(route.addr.to_string())?.into()),
            JValue::Byte(route.metric as _),
            JValue::Int(route.rt as _),
        ],
    )?;
    Ok(rs.as_raw())
}

fn peer_device_info_parse(
    env: &mut JNIEnv,
    peer: PeerDeviceInfo,
    route: JObject,
) -> Result<jobject, Error> {
    let virtual_ip = u32::from(peer.virtual_ip);
    let name = peer.name.to_string();
    let status = format!("{:?}", peer.status);
    let rs = env.new_object(
        "top/wherewego/vnt/jni/PeerRouteInfo",
        "(ILjava/lang/String;Ljava/lang/String;Ltop/wherewego/vnt/jni/Route;)V",
        &[
            JValue::Int(virtual_ip as jint),
            JValue::Object(&env.new_string(name)?.into()),
            JValue::Object(&env.new_string(status)?.into()),
            JValue::Object(&route),
        ],
    )?;
    Ok(rs.as_raw())
}
