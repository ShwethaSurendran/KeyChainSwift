//
//  KeyChainSwiftDelete.swift
//  KeyChainSwift
//
//

import Foundation

extension KeyChainSwift {
    
    public func delete(forKey: String,
                       withAccessType: CFString? = nil) throws -> Bool {
        var query : [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: withAccessType ?? kSecAttrAccessibleWhenUnlocked,
            kSecAttrAccount as String: forKey
        ]
        
        addAccessGroupIfAvailable(&query)
        
        let resultStatus = SecItemDelete(query as CFDictionary)
        if resultStatus == noErr {
            return true
        } else {
            throw KeychainError.status(getSecCopyErrorMessage(resultStatus))
        }
    }
    
    public func deleteAll() throws -> Bool {
        var query: [String: Any] = [ kSecClass as String : kSecClassGenericPassword ]
        let resultStatus = SecItemDelete(query as CFDictionary)
        if resultStatus == noErr {
            return true
        } else {
            throw KeychainError.status(getSecCopyErrorMessage(resultStatus))
        }
    }
}
