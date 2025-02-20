use std::any::type_name;

/// 打印变量类型
pub fn print_type_of<T>(_: &T) -> &'static str{
    print!("类型是: {}", type_name::<T>());
    type_name::<T>()
}

/// String相关方法
/// 将Vec<u8>转String
pub fn vec_to_string(vec: Vec<u8>) -> String {
    String::from_utf8_lossy(&vec).to_string()
}