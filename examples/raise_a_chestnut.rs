use wgq_rust;


fn main(){
   let result = 33;
   wgq_rust::print_type_of(&result);

   test_rsa();
   test_bcrypt();
}

fn test_rsa(){
   //测试加解密
   let cmsg = "我不知道你在说什么,rsut就是好用";
   //中文很多加密算法不支持,所以这里先转成base64
   let msg = wgq_rust::encrypt_use_base64(cmsg);


   //测试公钥加密
   //1.读取公钥
   let private_key = include_bytes!("public_key.pem");
   let encrypted_msg = wgq_rust::encrypt_use_rsa(&msg.as_bytes().to_vec(), private_key);
   let mut ss = "".to_string();
   if let Ok(encrypted_msg) = encrypted_msg {
      ss = wgq_rust::encrypt_use_base64(encrypted_msg);
       println!("加密后的消息:{:?}",ss);
   } else {
      print!("加密失败");
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
      println!("解密后的消息:{:?}",String::from_utf8(org_txt.unwrap()).unwrap());
   } else {
      print!("解密失败");
   };
}

fn test_bcrypt(){
   let password = "123456";
   let hash = wgq_rust::encrypt_use_bcrypt(password);
   // let aa = if let Ok(hash) = hash {
   //    hash
   // } else {
   //    "".to_string()
   // };
   let bb = hash.unwrap_or("".to_string());
   print!("{:?}",bb);
   // if let Ok(hash) = hash {
   //    let is_valid = wgq_rust::verify_use_bcrypt(password, &hash);
   //    if let Ok(is_valid) = is_valid {
   //       if is_valid {
   //          println!("密码正确");
   //       } else {
   //          println!("密码错误");
   //       }
   //    }     
   // }

   let is_valid = wgq_rust::verify_use_bcrypt(password, &bb);
   if let Ok(is_valid) = is_valid {
      if is_valid {
         println!("密码正确");
      } else {
         println!("密码错误");
      }
   }  
}