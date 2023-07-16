use std::ptr;
use jni::errors::Error;
use jni::JNIEnv;
use jni::objects::{JClass, JObject, JValue};
use jni::sys::{jboolean, jbyte, jint, jlong, jobject, jobjectArray, jsize};
use switch::channel::Route;
use switch::core::sync::SwitchSync;
use switch::handle::PeerDeviceInfo;

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_switchjni_Switch_stop0(
    _env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
) {
    let switch = raw_switch as *mut SwitchSync;
    let _ = (&*switch).stop();
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_switchjni_Switch_waitStop0(
    _env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
) {
    let switch = raw_switch as *mut SwitchSync;
    let _ = (&mut *switch).wait_stop();
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_switchjni_Switch_waitStopMs0(
    _env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
    ms: jlong,
) -> jboolean {
    let switch = raw_switch as *mut SwitchSync;
    if (&mut *switch).wait_stop_ms(ms as _) {
        jni::sys::JNI_TRUE
    } else {
        jni::sys::JNI_FALSE
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_switchjni_Switch_drop0(
    _env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
) {
    let switch = raw_switch as *mut SwitchSync;
    let _ = Box::from_raw(switch).stop();
}

#[no_mangle]
pub unsafe extern "C" fn Java_top_wherewego_switchjni_Switch_list0(
    mut env: JNIEnv,
    _class: JClass,
    raw_switch: jlong,
) -> jobjectArray {
    let switch = raw_switch as *mut SwitchSync;
    let switch = &mut *switch;
    let list = switch.device_list();

    let arr = match env.new_object_array(
        list.len() as jsize,
        "top/wherewego/switchjni/PeerDeviceInfo",
        JObject::null(),
    ) {
        Ok(arr) => { arr }
        Err(e) => {
            env.throw_new("java/lang/RuntimeException", format!("error:{:?}", e))
                .expect("throw");
            return ptr::null_mut();
        }
    };
    for (index, peer) in list.into_iter().enumerate() {
        let route = if let Some(route) = switch.route(&peer.virtual_ip) {
            match route_parse(&mut env, route) {
                Ok(route) => {
                    JObject::from_raw(route)
                }
                Err(_) => {
                    JObject::null()
                }
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
    let address = route.addr.to_string();
    let metric = route.metric;
    let rt = route.rt;
    let rs = env.new_object(
        "top/wherewego/switchjni/Route",
        "(Ljava/lang/String;BI)V",
        &[JValue::Object(&env.new_string(address)?.into()),
            JValue::Byte(metric as jbyte),
            JValue::Int(rt as jint)],
    )?;
    Ok(rs.as_raw())
}

fn peer_device_info_parse(env: &mut JNIEnv, peer: PeerDeviceInfo, route: JObject) -> Result<jobject, Error> {
    let virtual_ip = u32::from(peer.virtual_ip);
    let name = peer.name.to_string();
    let status = format!("{:?}", peer.status);
    let rs = env.new_object(
        "top/wherewego/switchjni/PeerDeviceInfo",
        "(ILjava/lang/String;Ljava/lang/String;Ltop/wherewego/switchjni/Route;)V",
        &[JValue::Int(virtual_ip as jint),
            JValue::Object(&env.new_string(name)?.into()),
            JValue::Object(&env.new_string(status)?.into()),
            JValue::Object(&route)],
    )?;
    Ok(rs.as_raw())
}