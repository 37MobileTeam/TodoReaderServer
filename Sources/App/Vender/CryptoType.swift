//
//  CryptoType.swift
//  PassionKit
//
//  Created by lory on 2022/10/26.
//  Copyright © 2022 sqsy. All rights reserved.
//

import Foundation

/// 网关加解密类型
public enum CryptoType: Int {
    /// 不加密，即使使用https也是明文传输，容易被串改（不推荐）
    case plainText = 1
    /// 加密1 （新SDK） （百香果当前使用）（推荐）
    case encryptAESECB
    /// 统一网关加解密
    case encryptAES256CBC
}
