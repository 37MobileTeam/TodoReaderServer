//
//  String+Base64url.swift
//  App
//
//  Created by lory on 2022/12/13.
//

import Foundation

private let kBase64Character = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"

extension String {
    var base64urlToBase64: String {
        var base64 = self.replacingOccurrences(of: "-", with: "+")
                         .replacingOccurrences(of: "_", with: "/")
        if base64.count % 4 != 0 {
            // base64在填充之前总是产生偶数个字符, 取模就不会为1, 因此不会填充成3个等号(===)
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }
        return base64
    }
    
    func urlEncodeString() -> String {
        self.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: kBase64Character))!
    }
}
