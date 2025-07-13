//
//  KeyChainSwiftUpdate.swift
//  KeyChainSwift
//
//

import Foundation

extension KeyChainSwift {
    
    public func update(_ value: String,
                    forKey: String,
                    withAccessType: CFString? = nil) throws -> Bool {
        guard let data = value.data(using: String.Encoding.utf8) else {
            throw KeychainError.invalidData
        }
        
        return try update(data, forKey: forKey, withAccessType: withAccessType)
    }
    
    public func update(_ value: Bool,
                    forKey: String,
                    withAccessType: CFString? = nil) throws -> Bool {
        let bool: UInt8 = value ? 1 : 0
        
        return try update(Data([bool]), forKey: forKey, withAccessType: withAccessType)
    }
    
    public func update(_ data: Data,
                    forKey: String,
                    withAccessType: CFString? = nil) throws -> Bool {
        var query : [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: withAccessType ?? kSecAttrAccessibleWhenUnlocked,
            kSecAttrAccount as String: forKey
        ]
        
        let newAttr = [
            kSecValueData as String: data
        ]
        
        addAccessGroupIfAvailable(&query)
        
        let resultStatus = SecItemUpdate(query as CFDictionary, newAttr as CFDictionary)
        if resultStatus == noErr {
            return true
        } else {
            throw KeychainError.status(getSecCopyErrorMessage(resultStatus))
        }
    }
    
}
