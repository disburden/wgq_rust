use std::any::type_name;

/// 打印变量类型
pub fn print_type_of<T>(_: &T) -> &'static str {
    let name = type_name::<T>();
    print!("类型是: {}\n", name);
    name
}

/// 打印变量类型,并把变量名称也打印,方便阅读
pub fn print_type_of_with_name<T>(_: &T, var_name: &str) -> &'static str {
    let name = type_name::<T>();
    print!("变量{}的类型是: {}\n", var_name, name);
    name
}

/// String相关方法
/// 将Vec<u8>转String
pub fn vec_to_string(vec: Vec<u8>) -> String {
    String::from_utf8_lossy(&vec).to_string()
}
