use std::any::type_name;
use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use chrono::format::ParseError;
use openssl::asn1::Asn1Type;

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


/// 将字符串转换为日期
/// date_str: 带时区的日期字符串，包括
/// 符合RFC 3339 格式的日期字符串
/// "2025-03-16T23:55:36.000"
/// "2025-03-16 23:55:36.000Z"
/// 返回值: Result<DateTime<Utc>, ParseError>
pub fn parse_datetime(date_str: &str) -> Result<DateTime<Utc>, anyhow::Error> {
    // 尝试解析带时区的日期字符串（RFC 3339 格式）
    if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
        return Ok(dt.with_timezone(&Utc));
    }

    // 尝试解析带时区的日期字符串（自定义格式，例如 "2025-03-16 23:55:36.000Z"）
    if let Ok(dt) = DateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S%.fZ") {
        return Ok(dt.with_timezone(&Utc));
    }

    // 尝试解析不带时区的日期字符串（假设为 UTC 时间）
    if let Ok(ndt) = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S%.f") {
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }

    // 如果都不匹配，返回错误
    anyhow::bail!("无法解析日期字符串");
}