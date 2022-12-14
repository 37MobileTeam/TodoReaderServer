//
//  Data+Base64url.swift
//  App
//
//  Created by lory on 2022/12/13.
//

import Foundation

extension Data {
    func hexadecimalString() -> String {
        let string = NSMutableString(capacity: count * 2)
        var byte: UInt8 = 0
        for idx in 0 ..< count {
            copyBytes(to: &byte, from: idx..<index(after: idx))
            string.appendFormat("%02x", byte)
        }

        return string as String
    }
    var hexString: String {
        return self.hexadecimalString()
    }
    var base64String: String {
        return self.base64EncodedString(options: NSData.Base64EncodingOptions())
    }
    
    var base64Url: String {
        return self.base64EncodedString(options: NSData.Base64EncodingOptions())
                        .replacingOccurrences(of: "/", with: "_")
                        .replacingOccurrences(of: "+", with: "-")
                        .replacingOccurrences(of: "=", with: "")
    }
    
    func arrayOfBytes() -> [UInt8] {
        let count = self.count / MemoryLayout<UInt8>.size
        var bytesArray = [UInt8](repeating: 0, count: count)
        (self as NSData).getBytes(&bytesArray, length: count * MemoryLayout<UInt8>.size)
        return bytesArray
    }
}
