use jni::errors::Error;
use jni::objects::{JIntArray, JObject, JObjectArray, JString};
use jni::JNIEnv;

pub fn to_string_not_null(
    env: &mut JNIEnv,
    config: &JObject,
    name: &'static str,
) -> Result<String, Error> {
    let value = env.get_field(config, name, "Ljava/lang/String;")?.l()?;
    if value.is_null() {
        env.throw_new("java/lang/NullPointerException", name)
            .expect("throw");
        return Err(Error::NullPtr(name));
    }
    let binding = JString::from(value);
    let value = env.get_string(binding.as_ref())?;
    match value.to_str() {
        Ok(value) => Ok(value.to_string()),
        Err(_) => {
            env.throw_new("java/lang/RuntimeException", "not utf-8")
                .expect("throw");
            return Err(Error::JavaException);
        }
    }
}

pub fn to_string(env: &mut JNIEnv, config: &JObject, name: &str) -> Result<Option<String>, Error> {
    let value = env.get_field(config, name, "Ljava/lang/String;")?.l()?;
    if value.is_null() {
        return Ok(None);
    }
    let tmp = JString::from(value);
    let value = env.get_string(tmp.as_ref())?;
    match value.to_str() {
        Ok(value) => Ok(Some(value.to_string())),
        Err(_) => {
            env.throw_new("java/lang/RuntimeException", "not utf-8")
                .expect("throw");
            return Err(Error::JavaException);
        }
    }
}

pub fn to_string_array_not_null(
    env: &mut JNIEnv,
    config: &JObject,
    name: &str,
) -> Result<Vec<String>, Error> {
    match to_string_array(env, config, name)? {
        None => {
            env.throw_new("java/lang/NullPointerException", name)
                .expect("throw");
            return Err(Error::JavaException);
        }
        Some(rs) => Ok(rs),
    }
}

pub fn to_string_array(
    env: &mut JNIEnv,
    config: &JObject,
    name: &str,
) -> Result<Option<Vec<String>>, Error> {
    let value = env.get_field(config, name, "[Ljava/lang/String;")?.l()?;
    if value.is_null() {
        return Ok(None);
    }
    let arr = JObjectArray::from(value);
    let len = env.get_array_length(&arr)?;
    let mut rs = Vec::with_capacity(len as usize);
    for index in 0..len {
        let object = env.get_object_array_element(&arr, index)?;
        if object.is_null() {
            env.throw_new(
                "java/lang/NullPointerException",
                format!("{},index={}", name, index),
            )
            .expect("throw");
            return Err(Error::JavaException);
        }
        match env.get_string(JString::from(object).as_ref())?.to_str() {
            Ok(value) => {
                rs.push(value.to_string());
            }
            Err(_) => {
                env.throw_new("java/lang/RuntimeException", "not utf-8")
                    .expect("throw");
                return Err(Error::JavaException);
            }
        }
    }
    Ok(Some(rs))
}

pub fn to_i32_array(
    env: &mut JNIEnv,
    config: &JObject,
    name: &str,
) -> Result<Option<Vec<i32>>, Error> {
    let obj = env.get_field(&config, name, "[I")?.l()?;
    if obj.is_null() {
        Ok(None)
    } else {
        let j_arr = JIntArray::from(obj);
        let len = env.get_array_length(&j_arr)?;
        let mut arr = vec![0i32; len as usize];
        env.get_int_array_region(j_arr, 0, &mut arr)?;
        Ok(Some(arr))
    }
}
pub fn to_integer(env: &mut JNIEnv, config: &JObject, name: &str) -> Result<Option<i32>, Error> {
    let value = env.get_field(config, name, "Ljava/lang/Integer;")?.l()?;
    if value.is_null() {
        return Ok(None);
    }
    // 调用 intValue
    return Ok(Some(
        env.call_method(value, "intValue", "()I", &[])?.i()? as _
    ));
}
