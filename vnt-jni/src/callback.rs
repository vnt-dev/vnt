use std::sync::Arc;

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};
use spki::der::pem::LineEnding;
use spki::EncodePublicKey;

use vnt::handle::callback::ConnectInfo;
#[cfg(target_os = "android")]
use vnt::handle::callback::DeviceConfig;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use vnt::DeviceInfo;
use vnt::{ErrorInfo, HandshakeInfo, PeerClientInfo, RegisterInfo, VntCallback};

#[derive(Clone)]
pub struct CallBack {
    jvm: Arc<JavaVM>,
    this: GlobalRef,
    connect_info_class: GlobalRef,
    handshake_info_class: GlobalRef,
    error_info_class: GlobalRef,
    register_info_class: GlobalRef,
    #[cfg(target_os = "android")]
    device_config_class: GlobalRef,
    peer_client_info_class: GlobalRef,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    device_info_class: GlobalRef,
}

unsafe impl Send for CallBack {}

fn find_class_global_ref(env: &mut JNIEnv, class: &str) -> jni::errors::Result<GlobalRef> {
    let class = env.find_class(class)?;
    env.new_global_ref(class)
}
impl CallBack {
    pub fn new(jvm: JavaVM, this: GlobalRef) -> jni::errors::Result<Self> {
        let mut env = jvm.attach_current_thread_as_daemon()?;
        let connect_info_class =
            find_class_global_ref(&mut env, "top/wherewego/vnt/jni/param/ConnectInfo")?;
        let handshake_info_class =
            find_class_global_ref(&mut env, "top/wherewego/vnt/jni/param/HandshakeInfo")?;
        let error_info_class =
            find_class_global_ref(&mut env, "top/wherewego/vnt/jni/param/ErrorInfo")?;
        let register_info_class =
            find_class_global_ref(&mut env, "top/wherewego/vnt/jni/param/RegisterInfo")?;
        #[cfg(target_os = "android")]
        let device_config_class = crate::callback::find_class_global_ref(
            &mut env,
            "top/wherewego/vnt/jni/param/DeviceConfig",
        )?;
        let peer_client_info_class =
            find_class_global_ref(&mut env, "top/wherewego/vnt/jni/param/PeerClientInfo")?;
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        let device_info_class =
            find_class_global_ref(&mut env, "top/wherewego/vnt/jni/param/DeviceInfo")?;
        Ok(Self {
            jvm: Arc::new(jvm),
            this,
            connect_info_class,
            handshake_info_class,
            error_info_class,
            register_info_class,
            #[cfg(target_os = "android")]
            device_config_class,
            peer_client_info_class,
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            device_info_class,
        })
    }
}

impl CallBack {
    fn success0(&self) -> jni::errors::Result<()> {
        let mut env = self.jvm.attach_current_thread_as_daemon()?;
        env.call_method(&self.this, "success", "()V", &[])?;
        Ok(())
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    fn create_tun0(&self, info: DeviceInfo) -> jni::errors::Result<()> {
        let mut env = self.jvm.attach_current_thread_as_daemon()?;
        let class = unsafe { JClass::from_raw(self.device_info_class.as_raw()) };
        let param = env.new_object(
            class,
            "(Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(&env.new_string(info.name)?.into()),
                JValue::Object(&env.new_string(info.version)?.into()),
            ],
        )?;
        env.call_method(
            &self.this,
            "createTun",
            "(Ltop/wherewego/vnt/jni/param/DeviceInfo;)V",
            &[JValue::Object(&param)],
        )?;
        Ok(())
    }
    fn connect0(&self, info: ConnectInfo) -> jni::errors::Result<()> {
        let mut env = self.jvm.attach_current_thread_as_daemon()?;
        let class = unsafe { JClass::from_raw(self.connect_info_class.as_raw()) };
        let param = env.new_object(
            class,
            "(JLjava/lang/String;)V",
            &[
                JValue::Long(info.count as _),
                JValue::Object(&env.new_string(info.address.to_string())?.into()),
            ],
        )?;
        env.call_method(
            &self.this,
            "connect",
            "(Ltop/wherewego/vnt/jni/param/ConnectInfo;)V",
            &[JValue::Object(&param)],
        )?;
        Ok(())
    }
    fn handshake0(&self, info: HandshakeInfo) -> jni::errors::Result<bool> {
        let mut env = self.jvm.attach_current_thread_as_daemon()?;
        let public_key = if let Some(public_key) = info.public_key {
            match public_key.to_public_key_pem(LineEnding::CRLF) {
                Ok(public_key) => env.new_string(public_key)?,
                Err(e) => {
                    log::warn!("{:?}", e);
                    JString::default()
                }
            }
        } else {
            JString::default()
        };
        let finger = if let Some(finger) = info.finger {
            env.new_string(finger)?
        } else {
            JString::default()
        };
        let class = unsafe { JClass::from_raw(self.handshake_info_class.as_raw()) };

        let param = env.new_object(
            class,
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(&public_key),
                JValue::Object(&finger),
                JValue::Object(&env.new_string(info.version)?.into()),
            ],
        )?;
        let rs = env.call_method(
            &self.this,
            "handshake",
            "(Ltop/wherewego/vnt/jni/param/HandshakeInfo;)Z",
            &[JValue::Object(&param)],
        )?;
        rs.z()
    }
    fn register0(&self, info: RegisterInfo) -> jni::errors::Result<bool> {
        let mut env = self.jvm.attach_current_thread_as_daemon()?;
        let class = unsafe { JClass::from_raw(self.register_info_class.as_raw()) };
        let param = env.new_object(
            class,
            "(III)V",
            &[
                JValue::Int(Into::<u32>::into(info.virtual_ip) as _),
                JValue::Int(Into::<u32>::into(info.virtual_netmask) as _),
                JValue::Int(Into::<u32>::into(info.virtual_gateway) as _),
            ],
        )?;
        let rs = env.call_method(
            &self.this,
            "register",
            "(Ltop/wherewego/vnt/jni/param/RegisterInfo;)Z",
            &[JValue::Object(&param)],
        )?;
        rs.z()
    }
    #[cfg(target_os = "android")]
    fn generate_tun0(&self, info: DeviceConfig) -> jni::errors::Result<u32> {
        let mut env = self.jvm.attach_current_thread_as_daemon()?;
        let class = unsafe { JClass::from_raw(self.device_config_class.as_raw()) };

        let object_array = env.new_object_array(
            info.external_route.len() as _,
            "java/lang/String",
            JObject::null(),
        )?;
        for (index, (network, mask)) in info.external_route.into_iter().enumerate() {
            let param =
                env.new_string(format!("{}/{}", network, u32::from(mask).leading_ones()))?;
            env.set_object_array_element(&object_array, index as _, &param)?;
        }
        let param = env.new_object(
            class,
            "(IIII)V",
            &[
                JValue::Int(Into::<u32>::into(info.virtual_ip) as _),
                JValue::Int(Into::<u32>::into(info.virtual_netmask) as _),
                JValue::Int(Into::<u32>::into(info.virtual_gateway) as _),
                JValue::Int(Into::<u32>::into(info.virtual_network) as _),
                JValue::Object(&object_array),
            ],
        )?;
        let rs = env.call_method(
            &self.this,
            "generateTun",
            "(Ltop/wherewego/vnt/jni/param/DeviceConfig;)I",
            &[JValue::Object(&param)],
        )?;
        rs.i().map(|v| v as _)
    }
    fn peer_client_list0(&self, info_vec: Vec<PeerClientInfo>) -> jni::errors::Result<()> {
        let mut env = self.jvm.attach_current_thread_as_daemon()?;
        let class = unsafe { JClass::from_raw(self.peer_client_info_class.as_raw()) };
        let object_array = env.new_object_array(info_vec.len() as _, &class, JObject::null())?;
        for (index, info) in info_vec.into_iter().enumerate() {
            let param = env.new_object(
                &class,
                "(ILjava/lang/String;ZZ)V",
                &[
                    JValue::Int(Into::<u32>::into(info.virtual_ip) as _),
                    JValue::Object(&env.new_string(info.name)?.into()),
                    JValue::Bool(info.status.is_online() as _),
                    JValue::Bool(info.client_secret as _),
                ],
            )?;
            env.set_object_array_element(&object_array, index as _, &param)?;
        }

        env.call_method(
            &self.this,
            "peerClientList",
            "([Ltop/wherewego/vnt/jni/param/PeerClientInfo;)V",
            &[JValue::Object(&object_array)],
        )?;
        Ok(())
    }

    fn error0(&self, info: ErrorInfo) -> jni::errors::Result<()> {
        let code: u8 = info.code.into();
        let mut env = self.jvm.attach_current_thread_as_daemon()?;
        let class = unsafe { JClass::from_raw(self.error_info_class.as_raw()) };
        let msg = if let Some(msg) = info.msg {
            env.new_string(msg)?
        } else {
            JString::default()
        };
        let param = env.new_object(
            class,
            "(ILjava/lang/String;)V",
            &[JValue::Int(code as _), JValue::Object(&msg.into())],
        )?;
        env.call_method(
            &self.this,
            "error",
            "(Ltop/wherewego/vnt/jni/param/ErrorInfo;)V",
            &[JValue::Object(&param)],
        )?;
        Ok(())
    }
    fn stop0(&self) -> jni::errors::Result<()> {
        let mut env = self.jvm.attach_current_thread_as_daemon()?;
        env.call_method(&self.this, "stop", "()V", &[])?;
        Ok(())
    }
}

impl VntCallback for CallBack {
    fn success(&self) {
        if let Err(e) = self.success0() {
            log::warn!("success {:?}", e);
        }
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    fn create_tun(&self, info: DeviceInfo) {
        if let Err(e) = self.create_tun0(info) {
            log::warn!("create_tun {:?}", e);
        }
    }

    fn connect(&self, info: ConnectInfo) {
        if let Err(e) = self.connect0(info) {
            log::warn!("connect {:?}", e);
        }
    }

    fn handshake(&self, info: HandshakeInfo) -> bool {
        self.handshake0(info).unwrap_or_else(|e| {
            log::warn!("handshake {:?}", e);
            false
        })
    }

    fn register(&self, info: RegisterInfo) -> bool {
        self.register0(info).unwrap_or_else(|e| {
            log::warn!("register {:?}", e);
            false
        })
    }
    #[cfg(target_os = "android")]
    fn generate_tun(&self, info: DeviceConfig) -> u32 {
        self.generate_tun0(info).unwrap_or_else(|e| {
            log::warn!("generate_tun {:?}", e);
            0
        })
    }

    fn peer_client_list(&self, info: Vec<PeerClientInfo>) {
        if let Err(e) = self.peer_client_list0(info) {
            log::warn!("peer_client_list {:?}", e);
        }
    }

    fn error(&self, info: ErrorInfo) {
        if let Err(e) = self.error0(info) {
            log::warn!("error {:?}", e);
        }
    }

    fn stop(&self) {
        if let Err(e) = self.stop0() {
            log::warn!("stop {:?}", e);
        }
    }
}
