//
//  Des.swift
//  RedCrystal
//
//  Created by 易承 on 2019/6/26.
//  Copyright © 2019 jiaruh. All rights reserved.
//

import Foundation
import CommonCrypto

enum AESError: Error {
    case invalidKeySize
    case stringToDataFailed
    case generateRandomIVFailed
    case encryptDataFailed
    case decryptDataFailed
    case dataToStringFailed
}

struct AES {
    let key: Data // <- Use `Data` instead of `NSData`

    private let ivSize: Int                     = kCCBlockSizeAES128
    private var options: CCOptions              = CCOptions(kCCOptionECBMode|kCCOptionPKCS7Padding)

    init(keyString: String, options: CCOptions = CCOptions(kCCOptionECBMode|kCCOptionPKCS7Padding) ) throws {
        guard keyString.count == kCCKeySizeAES128 || keyString.count == kCCKeySizeAES192 || keyString.count == kCCKeySizeAES256 else {
            throw AESError.invalidKeySize
        }
        guard let keyData: Data = keyString.data(using: .utf8) else {
            throw AESError.stringToDataFailed
        }
        self.key = keyData
        self.options = options
    }
}

extension AES {

    func encrypt(_ string: String, iv: String = "") throws -> Data {

        let dataToEncrypt: Data = Data(string.utf8)

        let bufferSize: Int = Swift.max(dataToEncrypt.count * 2, kCCBlockSizeAES128)
        var buffer = Data(count: bufferSize)
        var vector = Data()
        if iv.isEmpty {
            try? generateRandomIV(for: &vector)
        } else {
            if let data = iv.data(using: .utf8) {
                vector = data
            }
        }

        var numberBytesEncrypted: Int = 0

        do {
            try key.withUnsafeBytes { keyBytes in
                try dataToEncrypt.withUnsafeBytes { dataToEncryptBytes in
                    try buffer.withUnsafeMutableBytes { bufferBytes in

                        guard let keyBytesBaseAddress = keyBytes.baseAddress,
                            let dataToEncryptBytesBaseAddress = dataToEncryptBytes.baseAddress,
                            let bufferBytesBaseAddress = bufferBytes.baseAddress else {
                                throw AESError.encryptDataFailed
                        }

                        let cryptStatus: CCCryptorStatus = CCCrypt( // Stateless, one-shot encrypt operation
                            CCOperation(kCCEncrypt),                // op: CCOperation
                            CCAlgorithm(kCCAlgorithmAES128),        // alg: CCAlgorithm
                            options,                                // options: CCOptions
                            keyBytesBaseAddress,                    // key: the "password"
                            key.count,                              // keyLength: the "password" size
                            (vector as NSData).bytes,                   // iv: Initialization Vector
                            dataToEncryptBytesBaseAddress,          // dataIn: Data to encrypt bytes
                            dataToEncryptBytes.count,               // dataInLength: Data to encrypt size
                            bufferBytesBaseAddress,                 // dataOut: encrypted Data buffer
                            bufferSize,                             // dataOutAvailable: encrypted Data buffer size
                            &numberBytesEncrypted                   // dataOutMoved: the number of bytes written
                        )

                        guard cryptStatus == CCCryptorStatus(kCCSuccess) else {
                            throw AESError.encryptDataFailed
                        }
                    }
                }
            }
        } catch {
            throw AESError.encryptDataFailed
        }

        guard numberBytesEncrypted <= buffer.count else {
            throw AESError.dataToStringFailed
        }
        
        let encryptedData: Data = buffer[..<numberBytesEncrypted]
        return encryptedData
    }

    func decrypt(_ str: String, iv: String = "") throws -> String {
        guard let decryptData = Data(base64Encoded: str, options: .ignoreUnknownCharacters) else {
            return ""
        }

        let bufferSize: Int = Swift.max(decryptData.count * 2, kCCBlockSizeAES128)
        var buffer = Data(count: bufferSize)
        var vector = Data()
        if iv.isEmpty {
            try? generateRandomIV(for: &vector)
        } else {
            if let data = iv.data(using: .utf8) {
                vector = data
            }
        }

        var numberBytesDecrypted: Int = 0
        
        let cryptStatus: CCCryptorStatus = key.withUnsafeBytes {keyBytes in
            decryptData.withUnsafeBytes {dataBytes in
                buffer.withUnsafeMutableBytes {bufferBytes in
                    CCCrypt(         // Stateless, one-shot encrypt operation
                        CCOperation(kCCDecrypt),                        // op: CCOperation
                        CCAlgorithm(kCCAlgorithmAES128),                // alg: CCAlgorithm
                        options,                                        // options: CCOptions
                        keyBytes.baseAddress,                           // key: the "password"
                        key.count,                                      // keyLength: the "password" size
                        (vector as NSData).bytes,                           // iv: Initialization Vector
                        dataBytes.baseAddress!,                         // dataIn: Data to decrypt bytes
                        decryptData.count,                                     // dataInLength: Data to decrypt size
                        bufferBytes.baseAddress,                        // dataOut: decrypted Data buffer
                        bufferSize,                                     // dataOutAvailable: decrypted Data buffer size
                        &numberBytesDecrypted                           // dataOutMoved: the number of bytes written
                    )
                }
            }
        }

        guard cryptStatus == CCCryptorStatus(kCCSuccess) else {
            throw AESError.decryptDataFailed
        }
        guard numberBytesDecrypted <= buffer.count else {
            throw AESError.dataToStringFailed
        }
        let decryptedData = buffer[..<numberBytesDecrypted]

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw AESError.dataToStringFailed
        }

        return decryptedString
    }

}
// MARK: - Internal Extension

extension AES {

    /// Generates an `Initialization Vector` with random data for the `Cipher Block Chaining (CBC)` mode with
    /// block size `kCCBlockSizeAES128` and append it to the give `Data`.
    ///
    /// - Parameter data: The `Data` in which the generated `iv` will be attached into.
    /// - Throws: `AESError`
    func generateRandomIV(for data: inout Data) throws {

        try data.withUnsafeMutableBytes { dataBytes in

            guard let dataBytesBaseAddress = dataBytes.baseAddress else {
                throw AESError.generateRandomIVFailed
            }

            let status: Int32 = SecRandomCopyBytes(
                kSecRandomDefault,
                kCCBlockSizeAES128,
                dataBytesBaseAddress
            )

            guard status == 0 else {
                throw AESError.generateRandomIVFailed
            }
        }
    }
}
