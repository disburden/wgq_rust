use wgq_rust;


fn main(){
   let result = 33;
   wgq_rust::print_type_of(&result);
   wgq_rust::print_type_of_with_name(&result,"result");

   test_rsa();
   test_bcrypt();
   test_aes();
}

fn test_rsa(){
   //测试加解密
   let cmsg = "这个是用于测试rsa的消息".to_string();
   //中文很多加密算法不支持,所以这里先转成base64
   let msg = wgq_rust::encrypt_use_base64(cmsg);


   //测试公钥加密
   //1.读取公钥
   let private_key = include_bytes!("public_key.pem");
   let encrypted_msg = wgq_rust::encrypt_use_rsa(&msg.as_bytes().to_vec(), private_key);
   let mut ss = "".to_string();
   if let Ok(encrypted_msg) = encrypted_msg {
      ss = wgq_rust::encrypt_use_base64(encrypted_msg);
       println!("rsa加密后的消息:{:?}",ss);
   } else {
      print!("rsa加密失败");
   };

   //测试私钥解密
   //2.读取私钥
   let public_key = include_bytes!("private_key.pem");
   //将加密后的base64字符串解密
   let origin_cipher = wgq_rust::decrypt_use_base64(ss.as_str()).unwrap();
   // print!("解密base64后的消息:{:?}",origin_cipher);
   let decrypted_msg = wgq_rust::decrypt_use_rsa(&origin_cipher, public_key);
   if let Ok(decrypted_msg) = decrypted_msg {
      //解密后的decrypted_msg是个vec<u8>,要先转为String,方便后面转为str
      let sss = String::from_utf8(decrypted_msg).unwrap();
      let org_txt = wgq_rust::decrypt_use_base64(sss.as_str());
      println!("rsa解密后的消息:{:?}",String::from_utf8(org_txt.unwrap()).unwrap());
   } else {
      print!("rsa解密失败");
   };
}

fn test_bcrypt(){
   let password = "123456";
   let hash = wgq_rust::encrypt_use_bcrypt(password);
   let hashed_pass = hash.unwrap_or("".to_string());

   let is_valid = wgq_rust::verify_use_bcrypt(password, &hashed_pass);
   if let Ok(is_valid) = is_valid {
      if is_valid {
         println!("密码正确");
      } else {
         println!("密码错误");
      }
   }  
}

fn test_aes(){
   let message = "这是测试加密aes的字符串";
   let key = "123456789012345678901234567890ab";
   let iv = "cd1234567890";

   let cipher_text = wgq_rust::encrypt_use_aes(key, iv, message);
   println!("aes加密后的消息:{:?}",cipher_text);

   let cipher_bytes = wgq_rust::decrypt_use_base64(&cipher_text).unwrap();
   let plain_text = wgq_rust::decrypt_use_aes(key, iv, &cipher_bytes);
   println!("aes解密后的消息:{:?}",plain_text);
}