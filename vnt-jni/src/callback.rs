use std::sync::Arc;

use jni::objects::{GlobalRef, JString, JValue};
use jni::{JNIEnv, JavaVM};
use spki::der::pem::LineEnding;
use spki::EncodePublicKey;

use vnt::handle::callback::ConnectInfo;
use vnt::{DeviceInfo, ErrorInfo, HandshakeInfo, RegisterInfo, VntCallback};

#[derive(Clone)]
pub struct CallBack {
    jvm: Arc<JavaVM>,
    this: GlobalRef,
}

unsafe impl Send for CallBack {}

impl CallBack {
    pub fn new(jvm: JavaVM, this: GlobalRef) -> Self {
        Self {
            jvm: Arc::new(jvm),
            this,
        }
    }
}

impl CallBack {
    fn create_tun0(&self, info: DeviceInfo) -> jni::errors::Result<()> {
        let env = &mut self.jvm.attach_current_thread()? as &mut JNIEnv;
        let param = env.new_object(
            "top/wherewego/vnt/jni/param/DeviceInfo",
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
        let env = &mut self.jvm.attach_current_thread()? as &mut JNIEnv;
        let param = env.new_object(
            "top/wherewego/vnt/jni/param/ConnectInfo",
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
        let env = &mut self.jvm.attach_current_thread()? as &mut JNIEnv;
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
        let param = env.new_object(
            "top/wherewego/vnt/jni/param/HandshakeInfo",
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
        let env = &mut self.jvm.attach_current_thread()? as &mut JNIEnv;
        let param = env.new_object(
            "top/wherewego/vnt/jni/param/RegisterInfo",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(&env.new_string(info.virtual_ip.to_string())?.into()),
                JValue::Object(&env.new_string(info.virtual_netmask.to_string())?.into()),
                JValue::Object(&env.new_string(info.virtual_gateway.to_string())?.into()),
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
    fn error0(&self, info: ErrorInfo) -> jni::errors::Result<()> {
        let code: u8 = info.code.into();
        let env = &mut self.jvm.attach_current_thread()? as &mut JNIEnv;
        let msg = if let Some(msg) = info.msg {
            env.new_string(msg)?
        } else {
            JString::default()
        };
        let param = env.new_object(
            "top/wherewego/vnt/jni/param/ErrorInfo",
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
        let env = &mut self.jvm.attach_current_thread()? as &mut JNIEnv;
        env.call_method(&self.this, "error", "()V", &[])?;
        Ok(())
    }
}

impl VntCallback for CallBack {
    fn success(&self) {
    }
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
