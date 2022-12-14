//
//  String+MD5.swift
//  App
//
//  Created by lory on 2022/12/13.
//

import Foundation
import CommonCrypto

extension String {
    public func md5() -> String {
        let cStr = self.cString(using: String.Encoding.utf8)
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        CC_MD5(cStr!, (CC_LONG)(strlen(cStr!)), buffer)
        let result = NSMutableString()
        for idx in 0 ..< 16 {
            result.appendFormat("%02x", buffer[idx])
        }
        buffer.deallocate()
        return result as String
    }
}
